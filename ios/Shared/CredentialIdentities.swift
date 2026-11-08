import AuthenticationServices
import CryptoKit
import Foundation

/// One entry for iOS's credential identity store (QuickType bar and passkey sheet). Never
/// holds a secret: only the service, the user name and the item id (record identifier).
public struct IdentityRecord: Equatable, Hashable, Sendable {
    public enum Kind: Sendable { case password, passkey, oneTimeCode }
    public enum Service: Sendable { case domain, url }

    public var kind: Kind
    /// Domain or URL (password / one-time code), or the RP ID (passkey).
    public var service: String
    public var serviceType: Service
    /// User name (password, passkey) or label (one-time code).
    public var user: String
    /// The item id.
    public var recordId: String
    public var credentialId = Data()
    public var userHandle = Data()
    public var rank = 0
}

/// Maps the active account's logins to identity store entries.
///
/// A website becomes an identity by its effective match (the item's, or the default-match
/// setting for "Default"): "base domain" → a `.domain` identity of the base domain (iOS also
/// offers it on subdomains, like the matcher); "host" → a `.URL` identity of the origin;
/// "exact" / "starts with" → a `.URL` identity of the address. iOS matches these itself and
/// doesn't tell PassAuth the page when a suggestion is picked, so websites PassAuth can't
/// express this way are left out: regular expressions, "never", app websites, non-web schemes,
/// and anything covering the PassAuth server's own host (never fill the web vault).
public enum IdentityMapper {
    public static func records(_ entries: [Entry], defaultMatch: UrlMatch, server: String) -> [IdentityRecord] {
        let serverHost = UrlMatcher.parse(server)?.hostname ?? ""
        var out: [IdentityRecord] = []
        var seen = Set<IdentityRecord>()
        func add(_ r: IdentityRecord) { if seen.insert(r).inserted { out.append(r) } }
        for e in entries {
            guard let l = e.item.login else { continue }
            let rank = e.item.favorite ? 1 : 0
            let user = l.username.isEmpty ? e.item.name : l.username
            let services = l.urls.compactMap { service($0, defaultMatch: defaultMatch, serverHost: serverHost) }
            let hasTotp = !(l.totp ?? "").trimmingCharacters(in: .whitespaces).isEmpty
            for (svc, type) in services {
                if !l.password.isEmpty || !l.username.isEmpty {
                    add(IdentityRecord(kind: .password, service: svc, serviceType: type, user: user, recordId: e.id, rank: rank))
                }
                if hasTotp {
                    add(IdentityRecord(kind: .oneTimeCode, service: svc, serviceType: type, user: e.item.name.isEmpty ? user : e.item.name, recordId: e.id, rank: rank))
                }
            }
            for p in l.passkeys where p.algorithm == -7 && p.discoverable {
                guard let cid = PasskeyLogic.b64urlDecode(p.credentialId), !p.rpId.isEmpty else { continue }
                let handle = PasskeyLogic.b64urlDecode(p.userHandle) ?? Data()
                add(IdentityRecord(kind: .passkey, service: p.rpId.lowercased(), serviceType: .domain, user: p.userName.isEmpty ? p.userDisplayName : p.userName,
                                   recordId: e.id, credentialId: cid, userHandle: handle, rank: rank))
            }
        }
        return out
    }

    static func service(_ u: LoginUrl, defaultMatch: UrlMatch, serverHost: String) -> (String, IdentityRecord.Service)? {
        let match = u.match == .default ? defaultMatch : u.match
        guard !AutofillMatcher.isAppUrl(u), let p = UrlMatcher.parse(u.url), p.scheme == "http" || p.scheme == "https", !p.hostname.isEmpty else { return nil }
        let covers: (String) -> Bool = { domain in
            !serverHost.isEmpty && (serverHost == domain || serverHost.hasSuffix("." + domain))
        }
        switch match {
        case .domain, .default:
            let base = UrlMatcher.baseDomain(p.hostname)
            return covers(base) ? nil : (base, .domain)
        case .host:
            return covers(p.hostname) ? nil : (p.origin, .url)
        case .exact, .startsWith:
            return covers(p.hostname) ? nil : (p.href, .url)
        case .regex, .never:
            return nil
        }
    }

    /// The identity objects for the store (one-time codes only on iOS 18 and later).
    public static func identities(_ records: [IdentityRecord]) -> [any ASCredentialIdentity] {
        records.compactMap { r -> (any ASCredentialIdentity)? in
            switch r.kind {
            case .password:
                let id = ASPasswordCredentialIdentity(serviceIdentifier: serviceIdentifier(r), user: r.user, recordIdentifier: r.recordId)
                id.rank = r.rank
                return id
            case .passkey:
                let id = ASPasskeyCredentialIdentity(relyingPartyIdentifier: r.service, userName: r.user, credentialID: r.credentialId, userHandle: r.userHandle, recordIdentifier: r.recordId)
                id.rank = r.rank
                return id
            case .oneTimeCode:
                if #available(iOS 18.0, macOS 15.0, *) {
                    return ASOneTimeCodeCredentialIdentity(serviceIdentifier: serviceIdentifier(r), label: r.user, recordIdentifier: r.recordId)
                }
                return nil
            }
        }
    }

    static func serviceIdentifier(_ r: IdentityRecord) -> ASCredentialServiceIdentifier {
        ASCredentialServiceIdentifier(identifier: r.service, type: r.serviceType == .domain ? .domain : .URL)
    }
}

/// Keeps iOS's credential identity store in step with the active account (app and extension):
/// replaced after every sync and settings change, emptied on log out and when the active
/// account is locked after a switch. Written only while PassAuth is enabled for AutoFill.
@MainActor
public final class CredentialIdentitySync {
    private var last: String?
    /// Test hook: called with the records instead of writing to the system store.
    public var sink: (([IdentityRecord]?) -> Void)?

    public init() {}

    /// Whether PassAuth is turned on in Settings → General → AutoFill & Passwords.
    public static func isEnabled() async -> Bool {
        await withCheckedContinuation { c in
            ASCredentialIdentityStore.shared.getState { c.resume(returning: $0.isEnabled) }
        }
    }

    /// As `isEnabled()`, nil when the store doesn't answer in time (the iOS 27.0 simulator's
    /// store helper can't be reached).
    public static func isEnabled(timeout: Duration) async -> Bool? {
        let once = Once()
        return await withCheckedContinuation { (c: CheckedContinuation<Bool?, Never>) in
            ASCredentialIdentityStore.shared.getState { s in once.run { c.resume(returning: s.isEnabled) } }
            Task { try? await Task.sleep(for: timeout); once.run { c.resume(returning: nil) } }
        }
    }

    public func replace(_ records: [IdentityRecord]) {
        let key = Self.fingerprint(records)
        guard key != last else { return }
        last = key
        if let sink { return sink(records) }
        let identities = IdentityMapper.identities(records)
        pending = Task {
            guard await Self.isEnabled() else { return }
            try? await ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities)
        }
    }

    /// The last write started (AutoFill extension: waited for before completing a request,
    /// as iOS may end the extension right after).
    private var pending: Task<Void, Never>?

    /// Wait for the last identity store write (at most `timeout`: the store's XPC calls may
    /// never answer, e.g. on the iOS 27.0 simulator).
    public func flush(timeout: Duration = .seconds(3)) async {
        guard let task = pending else { return }
        let once = Once()
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            Task { await task.value; once.run { c.resume() } }
            Task { try? await Task.sleep(for: timeout); once.run { c.resume() } }
        }
    }

    private final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func run(_ body: () -> Void) {
            lock.lock()
            defer { lock.unlock() }
            guard !done else { return }
            done = true
            body()
        }
    }

    public func clear() {
        guard last != "" else { return }
        last = ""
        if let sink { return sink(nil) }
        pending = Task {
            try? await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
        }
    }

    /// Forget what was written (e.g. AutoFill was just turned on): the next replace writes again.
    public func invalidate() { last = nil }

    static func fingerprint(_ records: [IdentityRecord]) -> String {
        var h = SHA256()
        for r in records {
            h.update(data: Data("\(r.kind)|\(r.serviceType)|\(r.service)|\(r.user)|\(r.recordId)|\(r.rank)|".utf8))
            h.update(data: r.credentialId)
            h.update(data: r.userHandle)
        }
        return h.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
