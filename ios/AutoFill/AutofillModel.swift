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
    case list(pages: [String], passkey: PasskeyQuery?)
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

/// An `ASPasskeyCredentialRequestParameters` (a website asking to sign in with a passkey), as plain values.
struct PasskeyQuery {
    let rpId: String
    /// The credential ids the website accepts; empty: any discoverable passkey.
    let allowed: [Data]
    let clientDataHash: Data

    init(rpId: String, allowed: [Data], clientDataHash: Data) {
        self.rpId = rpId
        self.allowed = allowed
        self.clientDataHash = clientDataHash
    }

    init(_ p: ASPasskeyCredentialRequestParameters) {
        self.init(rpId: p.relyingPartyIdentifier, allowed: p.allowedCredentials, clientDataHash: p.clientDataHash)
    }
}

/// An `ASSavePasswordRequest`, as plain values (no iOS 26.2 types in the model).
struct SaveInfo {
    enum Event { case userInitiated, formDidDisappear, generatedPasswordFilled }
    /// The page or app domain as a matchable address (`AutofillMatcher.page`), nil for an app.
    let page: String?
    let username: String
    let password: String
    let event: Event

    init(page: String?, username: String, password: String, event: Event) {
        self.page = page
        self.username = username
        self.password = password
        self.event = event
    }

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

    init(page: String?, rules: PasswordRules?) {
        self.page = page
        self.rules = rules
    }

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
        /// "Add this site to a login": choose the login, then confirm it.
        case addSite
        case confirmAddSite
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
    /// Saving a login: the logins for the site it can update, and the chosen one (an entry id or
    /// `SaveLogic.newLogin`), preselected from the default plan.
    private(set) var saveTargets: [Entry] = []
    private(set) var saveTarget = SaveLogic.newLogin
    /// Saving a login that nothing for the site can take: the user's own logins for other sites
    /// with the same user name and password, offered as "Add this site" rows (`AddSite`), never preselected.
    private(set) var addToTargets: [Entry] = []
    /// "Add this site to a login" from the list: the login chosen in the picker.
    private(set) var addSiteChoice: Entry?
    /// The user picked the target themselves (kept when the vault catches up with the server).
    @ObservationIgnored private var saveTargetPicked = false
    /// A new login's id, the same for every Save of this sheet (an attempt whose answer was lost
    /// isn't saved twice; see `VaultRepository.createItem`).
    @ObservationIgnored private let newItemId = UUID().uuidString.lowercased()
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
        #if os(macOS)
        // A newer "Default URI match detection" picked in the desktop app's Settings.
        await DesktopSettings.adopt(repo)
        #endif
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
        // The copy on the device carries a warning for this login (its vault doesn't match its
        // record, or the server sent an older version of it): never handed over unseen. The
        // system asks again with the interface, where the warning is shown.
        if model.repo.vault?.fillNeedsReview(entry) ?? true {
            Self.log.notice("provideWithoutUserInteraction: the copy is warned, interface required")
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

    // MARK: What the prompt is about

    /// The site the request is about (its host), if it names one.
    var requestHost: String? {
        switch request {
        case .list(let pages, let passkey):
            return pages.first.map(AutofillMatcher.displayHost) ?? passkey?.rpId
        case .oneTimeCodes(let pages):
            return pages.first.map(AutofillMatcher.displayHost)
        case .credential(let r):
            if let id = r.credentialIdentity as? ASPasskeyCredentialIdentity { return id.relyingPartyIdentifier }
            return AutofillMatcher.page(r.credentialIdentity.serviceIdentifier).map(AutofillMatcher.displayHost)
        case .registerPasskey:
            return registration?.rpId
        case .save:
            return saveHost.isEmpty ? nil : saveHost
        case .generate(let info):
            return info.page.map(AutofillMatcher.displayHost)
        case .configuration:
            return nil
        }
    }

    /// Why the vault has to be unlocked, as the unlock prompt's title.
    var unlockTitle: String {
        switch request {
        case .list(_, let passkey): passkey == nil ? "Unlock to fill your login" : "Unlock to sign in"
        case .oneTimeCodes: "Unlock to fill your code"
        case .credential(let r):
            r.credentialIdentity is ASPasskeyCredentialIdentity ? "Unlock to sign in"
                : isOneTimeCode(r) ? "Unlock to fill your code" : "Unlock to fill your login"
        case .registerPasskey: "Unlock to save a passkey"
        case .save: "Unlock to save this login"
        case .configuration, .generate: "Unlock PassAuth"
        }
    }

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
        // The server requires two-step login first and there is no copy of the vault to work
        // from (e.g. right after signing in here): this extension can't set a method up.
        if repo.vault == nil && repo.state.twoStepRequired {
            return message(TwoStepGate.title, "Set up two-step login in the PassAuth app or the web vault, then try again.")
        }
        switch request {
        case .list, .oneTimeCodes:
            if let only = singleMatch {
                Self.log.notice("proceed: one login matches the page, filled without the list")
                return fill(only)
            }
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
                let choices = PasskeyLogic.saveChoices(v, rpId: r.rpId, userName: r.user)
                passkeyTargets = choices.map(\.entry)
                passkeyTarget = PasskeyLogic.defaultTarget(choices)
            }
            screen = .confirmPasskey
        case .credential(let r):
            await provide(r)
        case .save:
            switch savePlan {
            case .unchanged?: completeSave()
            case .noPassword?: cancel()
            default:
                resetSaveChoice()
                screen = .confirmSave
                Task {
                    // Offered from the copy on the device; the server may know more logins.
                    let before = repo.vault?.revision
                    await repo.refreshIfStale()
                    guard repo.vault?.revision != before, !busy else { return }
                    resetSaveChoice()
                    // Saved from another device in the meantime: nothing left to ask.
                    if case .unchanged? = savePlan, !saveTargetPicked { completeSave() }
                }
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
                return message("Passkey not found", "This passkey is no longer in your PassAuth vault. Sign in another way, then save a new passkey for this site.")
            }
            await assertPasskey(entry, passkey, rpId: id.relyingPartyIdentifier, clientDataHash: pk.clientDataHash)
            return
        }
        guard let entry = entry(recordId) else {
            // As for passkeys: the system drops the stale QuickType entry.
            Self.log.notice("provide: record not in the vault, credentialIdentityNotFound")
            return cancel(.credentialIdentityNotFound)
        }
        if repo.vault?.fillNeedsReview(entry) ?? true {
            // The copy carries a warning for this login: the list is shown (with the warning)
            // and the user picks the login there, instead of it being filled straight away.
            Self.log.notice("provide: the copy is warned, showing the list")
            reviewing = true
            screen = .list
            Task { await repo.refreshIfStale() }
            return
        }
        if isOneTimeCode(r) { fillCode(entry) } else { fill(entry) }
    }

    func entry(_ id: String?) -> Entry? {
        guard let id, let v = repo.vault else { return nil }
        return v.entries.first { $0.id == id }
    }

    // MARK: List

    /// A suggestion (QuickType) whose login carries a warning: the list is shown for it instead
    /// of filling at once (`provide`).
    private(set) var reviewing = false

    var pages: [String] {
        switch request {
        case .list(let p, _), .oneTimeCodes(let p): p
        case .credential(let r) where reviewing: AutofillMatcher.page(r.credentialIdentity.serviceIdentifier).map { [$0] } ?? []
        default: []
        }
    }

    var onlyCodes: Bool {
        if case .oneTimeCodes = request { return true }
        if case .credential(let r) = request, reviewing { return isOneTimeCode(r) }
        return false
    }

    var suggestions: [Entry] {
        guard let v = repo.vault else { return [] }
        let all = AutofillMatcher.candidates(pages, in: v, defaultMatch: state.settings.defaultMatch)
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
        return PasskeyLogic.matching(rpId: p.rpId, allowed: p.allowed, repo.passkeysFor(p.rpId))
            .sorted { $0.1.createdAt > $1.1.createdAt } // newest first
    }

    var passkeyRpId: String? {
        if case .list(_, let p?) = request { return p.rpId }
        return nil
    }

    /// "PassAuth…" on a page where exactly one login matches (setting `fillSingleMatch`): that login,
    /// filled without showing the list. Passwords only (not passkeys or codes), never a login whose copy
    /// carries a warning, and only when the page is known.
    var singleMatch: Entry? {
        guard state.settings.fillSingleMatch, case .list(let p, nil) = request, let page = p.first, let v = repo.vault else { return nil }
        guard let e = AutofillMatcher.onlyMatch(page, in: v, defaultMatch: state.settings.defaultMatch), !v.fillNeedsReview(e) else { return nil }
        return e
    }

    func pick(_ e: Entry) {
        if onlyCodes { fillCode(e) } else { fill(e) }
    }

    func pickPasskey(_ e: Entry, _ p: Passkey) {
        guard case .list(_, let params?) = request else { return }
        Task { await assertPasskey(e, p, rpId: params.rpId, clientDataHash: params.clientDataHash) }
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
            return message("No verification code", "This login has no valid authenticator key. Open the login in PassAuth and add the key again.")
        }
        if #available(iOS 18.0, macOS 15.0, *) {
            complete { ctx in ctx.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code), completionHandler: nil) }
        }
    }

    // MARK: Add this site to a login

    /// The page "Add this site to a login" adds to a login: the most specific page of a password
    /// list request, when it is a website (never for apps, verification codes or other requests).
    var addSitePage: String? {
        guard case .list = request, let page = pages.first, AddSite.origin(page) != nil else { return nil }
        return page
    }

    /// The site's host as the add-site screens name it ("play.google.com").
    var addSiteHost: String {
        guard let page = addSitePage, let p = UrlMatcher.parse(page) else { return "" }
        return p.host.hasPrefix("www.") ? String(p.host.dropFirst(4)) : p.host
    }

    /// The logins the site can be added to (`AddSite.targets`): editable, not matching it yet.
    var addSiteTargets: [Entry] {
        guard let page = addSitePage, let v = repo.vault else { return [] }
        return AddSite.targets(page: page, vault: v, defaultMatch: state.settings.defaultMatch)
    }

    func addSiteSearch(_ query: String) -> [Entry] {
        AutofillMatcher.search(query, addSiteTargets)
    }

    /// The warning for a login in a shared vault: everyone in it sees the new website.
    func addSiteWarning(_ e: Entry) -> String? {
        repo.vault.flatMap { AddSite.sharedWarning(e, in: $0) }
    }

    func openAddSite() {
        guard addSitePage != nil, !busy else { return }
        error = nil
        addSiteChoice = nil
        screen = .addSite
    }

    func chooseAddSite(_ e: Entry) {
        guard !busy else { return }
        error = nil
        addSiteChoice = e
        screen = .confirmAddSite
    }

    /// Back one step: from the confirmation to the picker, from the picker to the list.
    func addSiteBack() {
        guard !busy else { return }
        error = nil
        if screen == .confirmAddSite {
            addSiteChoice = nil
            screen = .addSite
        } else {
            screen = .list
        }
    }

    /// Add the site to the chosen login, then fill it (what the user wanted on this page). If
    /// adding fails, the error is shown and nothing is filled.
    func confirmAddSite() {
        guard let e = addSiteChoice, let page = addSitePage, !busy else { return }
        busy = true
        error = nil
        Task {
            do {
                _ = try await repo.addSite(e.id, page: page)
                // The identity store learns the new website (suggested above the keyboard next time).
                await repo.identities.flush()
                busy = false
                guard let fresh = entry(e.id) else {
                    self.error = "This login isn't in your vault any more."
                    return
                }
                fill(fresh)
            } catch {
                self.error = errorMessage(error)
                busy = false
            }
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
            return message("Can't use this passkey", "The saved passkey is damaged. Sign in another way, then save a new passkey for this site.")
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

    /// What saving would do by default, on the vault as currently open (the save itself syncs first).
    var savePlan: SaveLogic.Plan? {
        guard let info = saveInfo, let page = info.page, let v = repo.vault else { return nil }
        return SaveLogic.plan(page: page, username: info.username, password: info.password, vault: v, defaultMatch: state.settings.defaultMatch)
    }

    /// The login the sheet's "Save in" choice updates; nil for a new login.
    var saveUpdates: Entry? {
        saveTargets.first { $0.id == saveTarget }
    }

    /// The login the sheet's choice adds this site to ("Add this site" row); nil otherwise.
    var saveAddsTo: Entry? {
        addToTargets.first { $0.id == saveTarget }
    }

    func chooseSaveTarget(_ id: String) {
        guard !busy else { return }
        saveTarget = id
        saveTargetPicked = true
    }

    /// The name of the shared vault a "Save in" login (for a login or a passkey) is in, shown on
    /// its row; nil for the account's own vault.
    func sharedVaultName(_ e: Entry) -> String? {
        repo.vault?.sharedVaultName(e)
    }

    /// The warning under "Save in" when the chosen login is in a shared vault: saving there hands
    /// the password to that vault's members (a login somebody shared is never preselected).
    var saveWarning: String? {
        guard let v = repo.vault else { return nil }
        return SaveLogic.sharedWarning(saveUpdates, in: v)
    }

    /// The same warning for a new passkey: the chosen login is in a shared vault, so its members
    /// get the passkey (never preselected there either; see `PasskeyLogic.defaultTarget`).
    var passkeyWarning: String? {
        guard let v = repo.vault else { return nil }
        return PasskeyLogic.sharedWarning(passkeyTargets.first { $0.id == passkeyTarget }, in: v)
    }

    /// "Save in" for the vault as currently open: the logins for the site in the account's own
    /// vault, then those with the typed user name in shared vaults (never preselected), with the
    /// default plan's one selected, unless the user picked one that is still possible.
    private func resetSaveChoice() {
        guard let info = saveInfo, let page = info.page, let v = repo.vault else { return }
        saveTargets = SaveLogic.targets(page: page, username: info.username, password: info.password, vault: v, defaultMatch: state.settings.defaultMatch)
        addToTargets = AddSite.sameAccountElsewhere(page: page, username: info.username, password: info.password, saveTargets: saveTargets, vault: v,
                                                    defaultMatch: state.settings.defaultMatch)
        if saveTargetPicked && (saveTarget == SaveLogic.newLogin || (saveTargets + addToTargets).contains { $0.id == saveTarget }) { return }
        saveTargetPicked = false
        saveTarget = savePlan.map(SaveLogic.defaultTarget) ?? SaveLogic.newLogin
    }

    var saveHost: String {
        saveInfo?.page.map(AutofillMatcher.displayHost) ?? ""
    }

    /// Without a sheet: nothing to do (not offered, already saved), or the user already asked
    /// iOS to save and the vault opens without them (vault timeout "Never"). Everything else
    /// (locked vault, a save iOS didn't ask the user about, and an update of "the only login for
    /// the site" when no user name was typed: the user must see which login changes) goes to
    /// the confirmation sheet.
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
        case .noPassword: model.cancel()
        case .update(_, .only): model.cancel(.userInteractionRequired)
        case .create, .update:
            guard info.event == .userInitiated, let page = info.page else { return model.cancel(.userInteractionRequired) }
            // The same account is saved for another site: the sheet offers adding this site to it
            // instead of a second copy.
            if case .create = plan, let v = model.repo.vault,
               !AddSite.sameAccountElsewhere(page: page, username: info.username, password: info.password, saveTargets: [], vault: v,
                                             defaultMatch: model.state.settings.defaultMatch).isEmpty {
                return model.cancel(.userInteractionRequired)
            }
            do {
                // No target: the default plan of the synced vault; `saveLogin` refuses a rule-3
                // update there too (the sheet is shown instead).
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
        let add = saveAddsTo
        Task {
            defer { busy = false }
            do {
                if let add {
                    // The same account for another site: this site is added to it (re-checked
                    // after the sync: still the user's own login with this user name and password).
                    _ = try await repo.addSite(add.id, page: page, sameAccount: (info.username, info.password))
                    await repo.identities.flush()
                    return completeSave()
                }
                // Exactly what the sheet shows is applied. If the synced vault no longer allows
                // it (or would have made another default), nothing is written.
                _ = try await repo.saveLogin(page: page, username: info.username, password: info.password, target: saveTarget, isDefault: !saveTargetPicked,
                                             newItemId: newItemId)
                // iOS leaves the identity store to the provider: the new login is suggested next time.
                await repo.identities.flush()
                completeSave()
            } catch is VaultRepository.SaveChoiceChanged {
                // Show the choices of the vault as it is now and let the user confirm again.
                saveTargetPicked = false
                resetSaveChoice()
                switch savePlan {
                case .unchanged?: completeSave()
                default:
                    self.error = add == nil
                        ? "Your vault changed while this was open. Check “Save in”, then confirm again."
                        : "That login changed. Check where to save, then try again."
                }
            } catch {
                self.error = errorMessage(error)
                // The save synced first: the choices are those of the vault as it is now.
                resetSaveChoice()
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
