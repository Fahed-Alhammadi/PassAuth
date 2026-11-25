import Foundation
import Observation
import PassAuthKit
import UIKit
@preconcurrency import UserNotifications

// Sign-in request notifications: when a new device asks to sign in to an account, its server asks
// the PassAuth push relay to wake this iPhone (APNs). The notification has fixed text and no
// account data; tapping it opens the app, which asks the server for its open requests as usual
// (unlock first if needed) and shows the existing sign-in request sheet. The approval protocol is
// unchanged. Every signed-in account registers this device's token with its own server, and only
// while that server lists the `push` feature (`PUT /api/account/push`, `DELETE` on sign-out).

/// Pure rules (unit-tested).
enum PushRules {
    /// `/api/config` `features` entry of servers that send sign-in request notifications.
    static let feature = "push"
    /// Below `/api`.
    static let path = "/account/push"
    static let platform = "apns"

    /// The APNs environment the relay must use: debug builds are signed for development
    /// (aps-environment development, sandbox tokens), App Store/TestFlight builds for production.
    static func environment(debug: Bool) -> String { debug ? "sandbox" : "production" }

    static var environment: String {
        #if DEBUG
        environment(debug: true)
        #else
        environment(debug: false)
        #endif
    }

    /// The device token as lower-case hex (what the server and relay expect).
    static func hex(_ token: Data) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        out.reserveCapacity(token.count * 2)
        for b in token {
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 0x0f)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// What the server accepts: 64 to 200 hex characters.
    static func validToken(_ hex: String) -> Bool {
        (64...200).contains(hex.count) && hex.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    /// `PUT /api/account/push` body.
    static func registerBody(token: String, environment: String) -> JSON {
        ["platform": .string(platform), "token": .string(token), "environment": .string(environment)]
    }

    /// Whether a server with these `/api/config` features takes registrations (unknown: no).
    static func offered(features: [String]?) -> Bool { features?.contains(feature) ?? false }

    /// `UNAuthorizationStatus` raw value: 0 not determined, 1 denied, 2 authorized, 3 provisional,
    /// 4 ephemeral (App Clips).
    static func permission(_ raw: Int) -> PermissionStatus {
        switch raw {
        case 0: .notAsked
        case 1: .denied
        case 2, 3, 4: .allowed
        default: .unknown
        }
    }

    /// The notification is the relay's sign-in request one (`{"passauth":{"kind":"auth_request"}}`).
    static func isSignInRequest(_ userInfo: [AnyHashable: Any]) -> Bool {
        (userInfo["passauth"] as? [String: Any])?["kind"] as? String == "auth_request"
    }
}

/// Keeps this device's token registered with every signed-in account's server (each its own),
/// once per token and session in this app run. The network and `/api/config` are injected (tests).
@MainActor
final class PushRegistrar {
    /// One request to an account's server: method (PUT/DELETE) and body for `PushRules.path`.
    typealias Send = @MainActor (_ accountId: String, _ method: String, _ body: JSON?) async throws -> Void
    /// The account's server's `/api/config` `features` (nil: unknown).
    typealias Features = @MainActor (_ accountId: String) async -> [String]?

    private let send: Send
    private let features: Features
    let environment: String
    /// Account id → the token it was registered with in this run.
    private(set) var registered: [String: String] = [:]
    private var syncing = false
    private var again = false

    init(environment: String = PushRules.environment, send: @escaping Send, features: @escaping Features) {
        self.environment = environment
        self.send = send
        self.features = features
    }

    /// Register `token` with each signed-in account not registered with it yet; accounts no
    /// longer signed in are forgotten (their server dropped the row with the session).
    func sync(token: String?, signedIn: [String]) async {
        if syncing {
            again = true
            return
        }
        syncing = true
        defer { syncing = false }
        var token = token
        var ids = signedIn
        repeat {
            again = false
            registered = registered.filter { ids.contains($0.key) }
            guard let t = token, PushRules.validToken(t) else { return }
            for id in ids where registered[id] != t {
                guard PushRules.offered(features: await features(id)) else { continue }
                do {
                    try await send(id, "PUT", PushRules.registerBody(token: t, environment: environment))
                    registered[id] = t
                } catch {
                    // Offline, signed out meanwhile, push turned off by the admin (409): try at the next start.
                }
            }
            // Asked again meanwhile: one more pass with what it had (the caller passes the latest next time).
            token = t
            ids = signedIn
        } while again
    }

    /// Sign-out: remove this session's row (best effort; the server also drops it with the session).
    func unregister(_ id: String, timeout: Duration = .seconds(3)) async {
        registered[id] = nil
        let send = self.send
        let work = Task { @MainActor in try? await send(id, "DELETE", nil) }
        let timer = Task {
            try? await Task.sleep(for: timeout)
            work.cancel()
        }
        await work.value
        timer.cancel()
    }

    /// The account's next sign-in registers again.
    func forget(_ id: String) { registered[id] = nil }
}

/// The app's side of notifications: permission, the APNs token, registration with the servers,
/// and taps. One for the process (the app delegate sets it up before launch finishes, so a tap
/// that launched the app isn't missed).
@MainActor
@Observable
final class PushCenter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = PushCenter()

    /// What iOS says about notifications for PassAuth (unknown until read).
    private(set) var permission: PermissionStatus = .unknown
    /// Bumped when a sign-in request notification was tapped (or arrived while on screen):
    /// the app asks for the open requests again.
    private(set) var signInRequests = 0

    @ObservationIgnored private(set) var token: String?
    @ObservationIgnored private weak var repo: VaultRepository?
    @ObservationIgnored private var registrar: PushRegistrar?
    @ObservationIgnored private var started = false

    /// From `application(_:didFinishLaunchingWithOptions:)`.
    func start() {
        guard !started else { return }
        started = true
        UNUserNotificationCenter.current().delegate = self
        Task { await refreshPermission() }
    }

    /// From `AppModel`: the repository that knows the accounts and talks to their servers.
    func attach(_ repo: VaultRepository) {
        self.repo = repo
        registrar = PushRegistrar(
            send: { [weak repo] id, method, body in
                guard let repo else { return }
                _ = try await repo.api.call(id, PushRules.path, body: body, method: method)
            },
            features: { [weak repo] id in
                guard let repo else { return nil }
                return await Self.features(repo, id)
            })
    }

    /// The account's server's features, asked now (the admin can turn push off at any time);
    /// what was last kept with the account when the server can't be reached.
    private static func features(_ repo: VaultRepository, _ id: String) async -> [String]? {
        guard let a = repo.store.get().file.accounts[id], !a.server.isEmpty else { return nil }
        if let url = URL(string: a.server + "/api/config"), let (data, res) = try? await repo.api.get(url),
           res.statusCode == 200, let j = try? JSON.parse(data), let config = PublicConfig(json: j) {
            return config.features
        }
        return a.features
    }

    /// Read the permission again (app start, back on screen); allowed: get the token (iOS
    /// answers in the app delegate, then the accounts are registered).
    func refreshPermission() async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        permission = PushRules.permission(settings.authorizationStatus.rawValue)
        if permission == .allowed { UIApplication.shared.registerForRemoteNotifications() }
    }

    /// Ask iOS (shows the system prompt the first time only).
    func requestPermission() async {
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
        await refreshPermission()
    }

    /// The APNs token arrived (every start once allowed; it may change).
    func received(token data: Data) {
        token = PushRules.hex(data)
        Task { await sync() }
    }

    /// Accounts signed in on this device (locked or not: registering needs the session only).
    private var signedIn: [String] {
        guard let s = repo?.store.get() else { return [] }
        return s.file.order.filter { id in
            guard let a = s.file.accounts[id] else { return false }
            return !a.server.isEmpty && !a.email.isEmpty && s.tokens(id) != nil
        }
    }

    /// Register with every signed-in account's server that offers push (token arrived, sign-in).
    func sync() async {
        guard permission == .allowed, let registrar else { return }
        await registrar.sync(token: token, signedIn: signedIn)
    }

    /// Before signing an account out: its server forgets this device's token.
    func unregister(_ id: String) async {
        guard token != nil, let registrar else {
            registrar?.forget(id)
            return
        }
        await registrar.unregister(id)
    }

    /// Before signing every account out (vault timeout "Log out").
    func unregisterAll() async {
        let ids = signedIn
        let work = ids.map { id in Task { await self.unregister(id) } }
        for w in work { await w.value }
    }

    // MARK: UNUserNotificationCenterDelegate

    /// On screen: show the banner too (live sync usually opens the sheet already) and ask again.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        let signIn = PushRules.isSignInRequest(notification.request.content.userInfo)
        completionHandler([.banner, .list, .sound])
        if signIn { Task { @MainActor in self.signInRequests += 1 } }
    }

    /// Tapped: the app opens (unlock first when locked) and asks for the open requests.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        let signIn = response.actionIdentifier == UNNotificationDefaultActionIdentifier
            && PushRules.isSignInRequest(response.notification.request.content.userInfo)
        completionHandler()
        if signIn { Task { @MainActor in self.signInRequests += 1 } }
    }
}
