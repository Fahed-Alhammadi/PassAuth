import AuthenticationServices
import LocalAuthentication
import Observation
import PassAuthCore
import PassAuthKit
import os

/// What iOS asked the extension to do.
enum AutofillRequest {
    /// The password (and passkey) list: the key button in the QuickType bar, or "PassAuth" in
    /// the passkey sheet when no saved identity matched.
    case list(pages: [String], passkey: ASPasskeyCredentialRequestParameters?)
    /// Verification codes (iOS 18).
    case oneTimeCodes(pages: [String])
    /// A QuickType / passkey sheet suggestion that needs the vault unlocked or the user verified.
    case credential(any ASCredentialRequest)
    case registerPasskey(ASPasskeyCredentialRequest)
    /// PassAuth was just turned on in Settings.
    case configuration
    /// Save a login the user signed up or changed a password with (iOS 26.2).
    case save(SaveInfo)
    /// A password for a new-password field (iOS 26.2).
    case generate(GenerateInfo)
}

/// An `ASSavePasswordRequest`, as plain values (no iOS 26.2 types in the model).
struct SaveInfo {
    enum Event { case userInitiated, formDidDisappear, generatedPasswordFilled }
    /// The page or app domain as a matchable address (`AutofillMatcher.page`), nil for an app.
    let page: String?
    let username: String
    let password: String
    let event: Event

    #if os(iOS)
    @available(iOS 26.2, *)
    init(_ r: ASSavePasswordRequest) {
        page = AutofillMatcher.page(r.serviceIdentifier)
        username = r.credential.user
        password = r.credential.password
        switch r.event {
        case .userInitiated: event = .userInitiated
        case .generatedPasswordFilled: event = .generatedPasswordFilled
        default: event = .formDidDisappear
        }
    }
    #endif
}

/// An `ASGeneratePasswordsRequest`, as plain values.
struct GenerateInfo {
    let page: String?
    let rules: PasswordRules?

    #if os(iOS)
    @available(iOS 26.2, *)
    init(_ r: ASGeneratePasswordsRequest) {
        page = AutofillMatcher.page(r.serviceIdentifier)
        rules = PasswordGeneration.rules(field: r.passwordFieldPasswordRules, quirks: r.passwordRulesFromQuirks, confirm: r.confirmPasswordFieldPasswordRules)
    }
    #endif
}

/// The extension's state and actions. It runs in its own process: the vault is unlocked here
/// (master password, Face ID / Touch ID, or the kept keys of the vault timeout "Never"),
/// from the on-device copy of the last sync, and forgotten when iOS ends the extension.
@MainActor
@Observable
final class AutofillModel {
    enum Screen: Equatable {
        case loading
        case signedOut
        case unlock
        case list
        case confirmPasskey
        case message(title: String, body: String)
        case configured
        case confirmSave
        case generate
    }

    let repo: VaultRepository
    var request: AutofillRequest
    var screen: Screen = .loading
    /// The vault was unlocked in this flow (counts as user verification for passkeys).
    private(set) var unlockedHere = false
    var busy = false
    var error: String?
    /// Passkey registration: logins it can be saved in, and the chosen one (an entry id or `PasskeyLogic.newLogin`).
    var passkeyTargets: [Entry] = []
    var passkeyTarget = PasskeyLogic.newLogin
    /// Debug builds: memory measured around unlocking (for the extension memory limit).
    private(set) var memoryNote = ""
    @ObservationIgnored weak var context: ASCredentialProviderExtensionContext?
    @ObservationIgnored private var finished = false
    /// Outcomes only, never sites, names or secrets (`subsystem == "io.passauth.autofill"`).
    static let log = Logger(subsystem: "io.passauth.autofill", category: "model")
    /// Password generation: the offered passwords and how they were made.
    private(set) var generated: [PasswordGeneration.Candidate] = []
    private(set) var generatePlan: PasswordGeneration.Plan?

    init(request: AutofillRequest) {
        self.request = request
        #if os(macOS)
        // macOS: the desktop app's extension has its own sign-in and owns its state (no app shares it).
        let store = SecureStore(role: .app)
        #else
        let store = SecureStore(role: .appExtension)
        #endif
        let api = ApiClient(store: store)
        repo = VaultRepository(store: store, api: api)
        repo.preferCache = true
    }

    var state: AppState { repo.state }

    // MARK: Start

    func start() async {
        repo.store.load()
        // Generating needs only the generator settings, not the vault.
        if case .generate = request {
            regenerate()
            screen = .generate
            return
        }
        // The state exists but couldn't be read (Keychain refused, e.g. right after login or
        // wake): not "signed out" (a new sign-in's writes would be refused, as the unread state
        // must never be replaced).
        if repo.store.exists && !repo.store.loaded {
            Self.log.error("start: state exists but can't be read")
            return message("Can't read PassAuth's data", "Try again in a moment.")
        }
        let s = repo.state
        guard repo.store.exists, s.status == .locked || s.status == .unlocked else {
            screen = .signedOut
            return
        }
        // Not offered here: nothing to unlock for.
        if case .save(let info) = request, saveBlocked(info) != nil { return cancel() }
        // Vault timeout "Never": the keys kept in the Keychain open the vault without a prompt.
        await reopenKept()
        if repo.isUnlocked {
            await proceed()
        } else {
            screen = .unlock
        }
    }

    /// Fill without showing anything: only when the vault opens without the user (vault
    /// timeout "Never") and the login (or code) is still in the vault. Passkeys always go
    /// through the interface (user verification).
    static func provideWithoutUserInteraction(_ request: any ASCredentialRequest, context: ASCredentialProviderExtensionContext) async {
        let model = AutofillModel(request: .credential(request))
        model.context = context
        model.repo.store.load()
        guard request.type == .password || model.isOneTimeCode(request), model.repo.store.exists else {
            return model.cancel(.userInteractionRequired)
        }
        await model.reopenKept()
        guard model.repo.isUnlocked, let entry = model.entry(request.credentialIdentity.recordIdentifier) else {
            return model.cancel(.userInteractionRequired)
        }
        if request.type == .password {
            model.fill(entry)
        } else {
            model.fillCode(entry)
        }
    }

    private func isOneTimeCode(_ r: any ASCredentialRequest) -> Bool {
        if #available(iOS 18.0, macOS 15.0, *) { return r.type == .oneTimeCode }
        return false
    }

    /// Open the vault without the user: the keys kept for the vault timeout "Never" and, on
    /// macOS, those kept until the vault timeout passes (`TimedUnlock`).
    func reopenKept() async {
        _ = await repo.restorePersisted()
        #if os(macOS)
        if !repo.isUnlocked { _ = await TimedUnlock.restore(repo) }
        #endif
    }

    #if os(macOS)
    /// macOS: the extension signed in by itself (its own sign-in screens); continue the request.
    func signedIn() async {
        unlockedHere = true
        TimedUnlock.keep(repo)
        await proceed()
    }
    #endif

    // MARK: Unlock

    /// Master password unlock runs Argon2id with the account's memory cost inside the
    /// extension, which iOS limits in memory. Refuse it up front when it can't fit
    /// (`os_proc_available_memory`, device only) instead of being killed mid-way.
    var masterPasswordFits: Bool {
        guard let available = MemoryStats.available() else { return true }
        let need = UInt64(repo.kdfMemoryKiB ?? 128 * 1024) * 1024 + 16 * 1_048_576
        return available >= need
    }

    func unlock(password: String, secretKey: String) {
        guard !busy, !password.isEmpty else { return }
        busy = true
        error = nil
        Task {
            let before = MemoryStats.footprint().current
            do {
                try await repo.unlock(password: password, secretKey: secretKey.isEmpty ? nil : secretKey)
                noteMemory("master password", before)
                unlockedHere = true
                #if os(macOS)
                TimedUnlock.keep(repo)
                #endif
                busy = false
                await proceed()
            } catch {
                self.error = errorMessage(error)
                busy = false
            }
        }
    }

    func unlockWithBiometric() {
        guard !busy else { return }
        busy = true
        error = nil
        Task {
            do {
                let before = MemoryStats.footprint().current
                if try await repo.unlockWithBiometric(reason: saveInfo == nil ? "Unlock PassAuth to fill" : "Unlock PassAuth to save the login") {
                    noteMemory("biometric", before)
                    unlockedHere = true
                    #if os(macOS)
                    TimedUnlock.keep(repo)
                    #endif
                    busy = false
                    await proceed()
                    return
                }
            } catch { self.error = errorMessage(error) }
            busy = false
        }
    }

    private func noteMemory(_ how: String, _ before: UInt64) {
        #if DEBUG
        let f = MemoryStats.footprint()
        memoryNote = "unlock(\(how)) before \(MemoryStats.mb(before)) after \(MemoryStats.mb(f.current)) peak \(MemoryStats.mb(f.peak)) kdf \((repo.kdfMemoryKiB ?? 0) / 1024) MiB"
        #endif
    }

    // MARK: After unlock

    private func proceed() async {
        switch request {
        case .list, .oneTimeCodes:
            screen = .list
            // The copy on the device opened instantly; catch up with the server in the background.
            Task { await repo.refreshIfStale() }
        case .configuration:
            repo.identities.invalidate()
            repo.refreshIdentities()
            screen = .configured
            Task { await repo.refreshIfStale() }
        case .registerPasskey:
            if let r = registration, let v = repo.vault {
                passkeyTargets = PasskeyLogic.saveTargets(v, rpId: r.rpId, userName: r.user)
                passkeyTarget = PasskeyLogic.defaultTarget(passkeyTargets, rpId: r.rpId)
            }
            screen = .confirmPasskey
        case .credential(let r):
            await provide(r)
        case .save:
            switch savePlan {
            case .unchanged?: completeSave()
            case .readOnly(let e)?:
                message("Can't update this login", "\(e.item.name) is in \(repo.vault?.vaultName(e.vaultId) ?? "a vault") that you can only view.")
            default:
                screen = .confirmSave
                Task { await repo.refreshIfStale() }
            }
        case .generate:
            screen = .generate
        }
    }

    private func provide(_ r: any ASCredentialRequest) async {
        let recordId = r.credentialIdentity.recordIdentifier
        if let pk = r as? ASPasskeyCredentialRequest {
            guard let id = pk.credentialIdentity as? ASPasskeyCredentialIdentity else { return cancel(.credentialIdentityNotFound) }
            let found = repo.passkeysFor(id.relyingPartyIdentifier).first { _, p in PasskeyLogic.b64urlDecode(p.credentialId) == id.credentialID }
            guard let (entry, passkey) = found else {
                return message("Passkey not found", "This passkey is no longer in your PassAuth vault.")
            }
            await assertPasskey(entry, passkey, rpId: id.relyingPartyIdentifier, clientDataHash: pk.clientDataHash)
            return
        }
        guard let entry = entry(recordId) else {
            // As for passkeys: the system drops the stale QuickType entry.
            Self.log.notice("provide: record not in the vault, credentialIdentityNotFound")
            return cancel(.credentialIdentityNotFound)
        }
        if isOneTimeCode(r) { fillCode(entry) } else { fill(entry) }
    }

    func entry(_ id: String?) -> Entry? {
        guard let id, let v = repo.vault else { return nil }
        return v.entries.first { $0.id == id }
    }

    // MARK: List

    var pages: [String] {
        switch request {
        case .list(let p, _), .oneTimeCodes(let p): p
        default: []
        }
    }

    var onlyCodes: Bool {
        if case .oneTimeCodes = request { return true }
        return false
    }

    var suggestions: [Entry] {
        guard let v = repo.vault else { return [] }
        let all = AutofillMatcher.candidates(pages, v.entries, defaultMatch: state.settings.defaultMatch)
        return onlyCodes ? all.filter { Clipboard.totp($0.item.login?.totp) != nil } : all
    }

    func searchResults(_ query: String) -> [Entry] {
        guard let v = repo.vault else { return [] }
        let found = AutofillMatcher.search(query, v.entries)
        return onlyCodes ? found.filter { Clipboard.totp($0.item.login?.totp) != nil } : found
    }

    /// Passkeys offered in the list for a passkey request.
    var passkeyChoices: [(Entry, Passkey)] {
        guard case .list(_, let p?) = request else { return [] }
        return PasskeyLogic.matching(rpId: p.relyingPartyIdentifier, allowed: p.allowedCredentials, repo.passkeysFor(p.relyingPartyIdentifier))
            .sorted { $0.1.createdAt > $1.1.createdAt } // newest first
    }

    var passkeyRpId: String? {
        if case .list(_, let p?) = request { return p.relyingPartyIdentifier }
        return nil
    }

    func pick(_ e: Entry) {
        if onlyCodes { fillCode(e) } else { fill(e) }
    }

    func pickPasskey(_ e: Entry, _ p: Passkey) {
        guard case .list(_, let params?) = request else { return }
        Task { await assertPasskey(e, p, rpId: params.relyingPartyIdentifier, clientDataHash: params.clientDataHash) }
    }

    // MARK: Fill

    func fill(_ e: Entry) {
        guard let l = e.item.login else { return }
        if state.settings.autoCopyTotp, let code = Clipboard.totp(l.totp) {
            Clipboard.copy(code, clearAfter: state.settings.clearClipboard)
        }
        complete { ctx in ctx.completeRequest(withSelectedCredential: ASPasswordCredential(user: l.username, password: l.password), completionHandler: nil) }
    }

    func fillCode(_ e: Entry) {
        guard let code = Clipboard.totp(e.item.login?.totp) else {
            return message("No verification code", "This login has no valid authenticator key.")
        }
        if #available(iOS 18.0, macOS 15.0, *) {
            complete { ctx in ctx.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code), completionHandler: nil) }
        }
    }

    // MARK: Passkeys

    /// Verify the user before a passkey is used or created: unlocking in this flow counts,
    /// otherwise Face ID / Touch ID or the device passcode.
    private func verifyUser(_ reason: String) async -> Bool {
        if unlockedHere { return true }
        let c = LAContext()
        var err: NSError?
        guard c.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
            // No passcode on the device: the explicit tap in PassAuth's sheet is the consent.
            return true
        }
        return (try? await c.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }

    private func assertPasskey(_ e: Entry, _ p: Passkey, rpId: String, clientDataHash: Data) async {
        guard await verifyUser("Sign in with your passkey") else { return }
        guard let key = PasskeyLogic.b64urlDecode(p.privateKey), let cid = PasskeyLogic.b64urlDecode(p.credentialId) else {
            return message("Can't use this passkey", "The saved passkey is damaged.")
        }
        do {
            let rp = rpId.lowercased()
            let a = try await Task.detached { try passkeyAssert(privateKeyPkcs8: key, rpId: rp, clientDataHash: clientDataHash) }.value
            let handle = PasskeyLogic.b64urlDecode(p.userHandle) ?? Data()
            let cred = ASPasskeyAssertionCredential(userHandle: handle, relyingParty: rp, signature: a.signature, clientDataHash: clientDataHash, authenticatorData: a.authenticatorData, credentialID: cid)
            complete { ctx in ctx.completeAssertionRequest(using: cred, completionHandler: nil) }
        } catch {
            message("Can't sign in with this passkey", errorMessage(error))
        }
    }

    var registration: (rpId: String, user: String)? {
        guard case .registerPasskey(let r) = request, let id = r.credentialIdentity as? ASPasskeyCredentialIdentity else { return nil }
        return (id.relyingPartyIdentifier, id.userName)
    }

    func savePasskey() {
        guard case .registerPasskey(let r) = request, let id = r.credentialIdentity as? ASPasskeyCredentialIdentity, !busy else { return }
        busy = true
        error = nil
        Task {
            defer { busy = false }
            guard await verifyUser("Save a passkey for \(id.relyingPartyIdentifier)") else { return }
            if !r.supportedAlgorithms.isEmpty && !r.supportedAlgorithms.contains(ASCOSEAlgorithmIdentifier(rawValue: PasskeyLogic.es256)) {
                return message("Can't save this passkey", "PassAuth creates ES256 passkeys only, and this website doesn't accept them.")
            }
            let rp = id.relyingPartyIdentifier.lowercased()
            // Checked only after the user agreed, so a website can't probe the vault silently.
            if #available(iOS 18.0, macOS 15.0, *), let excluded = r.excludedCredentials?.map(\.credentialID) {
                let all = repo.vault?.entries.flatMap { $0.item.login?.passkeys ?? [] } ?? []
                if PasskeyLogic.excludedExists(excluded, rpId: rp, all: all) {
                    return cancel(.matchedExcludedCredential)
                }
            }
            do {
                let created = try await Task.detached { try passkeyCreate(rpId: rp) }.value
                let p = PasskeyLogic.record(rpId: rp, userName: id.userName, userHandle: id.userHandle, created: created, now: Int64(Date().timeIntervalSince1970))
                try await repo.storePasskey(p, target: passkeyTarget)
                await repo.identities.flush()
                let cred = ASPasskeyRegistrationCredential(relyingParty: rp, clientDataHash: r.clientDataHash, credentialID: created.credentialId, attestationObject: created.attestationObject)
                complete { ctx in ctx.completeRegistrationRequest(using: cred, completionHandler: nil) }
            } catch {
                self.error = errorMessage(error)
            }
        }
    }

    // MARK: Save logins (iOS 26.2)

    var saveInfo: SaveInfo? {
        if case .save(let i) = request { return i }
        return nil
    }

    func saveBlocked(_ info: SaveInfo) -> SaveLogic.Blocked? {
        SaveLogic.blocked(page: info.page, password: info.password, settings: state.settings)
    }

    /// What saving would do, on the vault as currently open (the save itself syncs first).
    var savePlan: SaveLogic.Plan? {
        guard let info = saveInfo, let page = info.page, let v = repo.vault else { return nil }
        return SaveLogic.plan(page: page, username: info.username, password: info.password, vault: v, defaultMatch: state.settings.defaultMatch)
    }

    var saveHost: String {
        saveInfo?.page.map(AutofillMatcher.displayHost) ?? ""
    }

    /// Without a sheet: nothing to do (not offered, already saved), or the user already asked
    /// iOS to save and the vault opens without them (vault timeout "Never"). Everything else
    /// (locked vault, a save iOS didn't ask the user about) goes to the confirmation sheet.
    /// A generated password just filled into a form isn't saved yet: the submit that follows
    /// brings the user name too.
    static func saveWithoutUserInteraction(_ info: SaveInfo, context: ASCredentialProviderExtensionContext) async {
        let model = AutofillModel(request: .save(info))
        model.context = context
        model.repo.store.load()
        let s = model.repo.state
        guard model.repo.store.exists, s.status == .locked || s.status == .unlocked else { return model.cancel(.failed) }
        if model.saveBlocked(info) != nil || info.event == .generatedPasswordFilled { return model.cancel() }
        await model.reopenKept()
        guard model.repo.isUnlocked, let plan = model.savePlan else { return model.cancel(.userInteractionRequired) }
        switch plan {
        case .unchanged: model.completeSave()
        case .readOnly: model.cancel()
        case .create, .update:
            guard info.event == .userInitiated, let page = info.page else { return model.cancel(.userInteractionRequired) }
            do {
                _ = try await model.repo.saveLogin(page: page, username: info.username, password: info.password)
                await model.repo.identities.flush()
                model.completeSave()
            } catch {
                model.cancel(.userInteractionRequired)
            }
        }
    }

    func confirmSave() {
        guard let info = saveInfo, let page = info.page, !busy else { return }
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                _ = try await repo.saveLogin(page: page, username: info.username, password: info.password)
                // iOS leaves the identity store to the provider: the new login is suggested next time.
                await repo.identities.flush()
                completeSave()
            } catch {
                self.error = errorMessage(error)
            }
        }
    }

    /// "Never for this site": the page's base domain goes on the never-save list.
    func neverSaveHere() {
        guard !busy else { return }
        guard let key = saveInfo?.page.flatMap(SaveLogic.neverSaveKey) else { return cancel() }
        busy = true
        Task {
            await repo.updateSettings { s in if !s.neverSave.contains(key) { s.neverSave.append(key) } }
            busy = false
            cancel()
        }
    }

    private func completeSave() {
        #if os(iOS)
        if #available(iOS 26.2, *) {
            complete { ctx in ctx.completeSavePasswordRequest(completionHandler: nil) }
        }
        #endif
    }

    // MARK: Generate passwords (iOS 26.2)

    var generateInfo: GenerateInfo? {
        if case .generate(let i) = request { return i }
        return nil
    }

    func regenerate() {
        let r = PasswordGeneration.candidates(rules: generateInfo?.rules, user: state.settings.generator)
        generated = r.list
        generatePlan = r.plan
    }

    /// No sheet: the passwords go back to iOS, which shows them (strong, no special
    /// characters, passphrase; the user's preferred type first). The vault isn't needed.
    static func generateWithoutUserInteraction(_ info: GenerateInfo, context: ASCredentialProviderExtensionContext) {
        let model = AutofillModel(request: .generate(info))
        model.context = context
        model.repo.store.load()
        model.regenerate()
        guard !model.generated.isEmpty else { return model.cancel(.failed) }
        model.useGenerated(model.generated)
    }

    func useGenerated(_ list: [PasswordGeneration.Candidate]) {
        #if os(iOS)
        guard #available(iOS 26.2, *), !list.isEmpty else { return cancel(.failed) }
        let results = list.map { c in
            let kind: ASGeneratedPassword.Kind = switch c.kind {
            case .strong: .strong
            case .alphanumeric: .alphanumeric
            case .passphrase: .passphrase
            }
            return ASGeneratedPassword(kind: kind, value: c.value)
        }
        complete { ctx in ctx.completeGeneratePasswordRequest(results: results, completionHandler: nil) }
        #else
        cancel(.failed) // macOS has no password generation requests.
        #endif
    }

    // MARK: Finish

    func finishConfiguration() {
        guard !finished, context != nil else { return }
        finished = true
        endOfRequest()
        handOver { $0.completeExtensionConfigurationRequest() }
    }

    private func complete(_ body: @escaping @MainActor (ASCredentialProviderExtensionContext) -> Void) {
        guard !finished, context != nil else { return }
        finished = true
        // The sheet shows progress while `handOver` waits for the identity store (macOS).
        busy = true
        endOfRequest()
        handOver(body)
    }

    func cancel(_ code: ASExtensionError.Code = .userCanceled) {
        if case .configuration = request { return finishConfiguration() }
        guard !finished, context != nil else { return }
        finished = true
        endOfRequest()
        handOver { $0.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue)) }
    }

    /// Answer the system. macOS ends the extension right after, and nothing else writes the
    /// credential identity store there (on iOS the app does too), so the write started by the
    /// last sync or unlock must land first; otherwise Safari never learns which logins fit which
    /// site and only offers the full list.
    private func handOver(_ body: @escaping @MainActor (ASCredentialProviderExtensionContext) -> Void) {
        guard let context else { return }
        #if os(macOS)
        Task { @MainActor in
            await repo.identities.flush(timeout: .seconds(2))
            body(context)
        }
        #else
        body(context)
        #endif
    }

    /// macOS: drop kept keys that are past the vault timeout as each request ends.
    private func endOfRequest() {
        #if os(macOS)
        TimedUnlock.purgeExpired(repo)
        #endif
    }

    private func message(_ title: String, _ body: String) {
        screen = .message(title: title, body: body)
    }
}
