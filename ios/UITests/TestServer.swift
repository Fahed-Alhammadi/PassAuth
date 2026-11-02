import Foundation
import PassAuthCore

/// Talks to the throwaway server like another device would (OPAQUE and item encryption
/// from the Rust core): creates accounts and vaults, turns on two-step login and changes
/// items while the app is on screen.
@MainActor
final class TestServer {
    struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    final class Session {
        let email: String
        let account: Account
        var access: String
        var refresh: String
        init(email: String, account: Account, access: String, refresh: String) {
            self.email = email
            self.account = account
            self.access = access
            self.refresh = refresh
        }
    }

    let base: String
    init(_ base: String) { self.base = base }

    @discardableResult
    func call(_ method: String, _ path: String, _ body: [String: Any]? = nil, session: Session? = nil, headers: [String: String] = [:]) async throws -> [String: Any] {
        func send() async throws -> (Int, Data) {
            var req = URLRequest(url: URL(string: base + "/api" + path)!)
            req.httpMethod = method
            if let body {
                req.httpBody = try JSONSerialization.data(withJSONObject: body)
                req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            }
            if let session { req.setValue("Bearer \(session.access)", forHTTPHeaderField: "Authorization") }
            for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
            let (data, res) = try await URLSession.shared.data(for: req)
            return ((res as? HTTPURLResponse)?.statusCode ?? 0, data)
        }
        var (status, data) = try await send()
        if status == 401, let session {
            let r = try await call("POST", "/auth/refresh", ["refresh_token": session.refresh])
            session.access = r["access_token"] as? String ?? ""
            session.refresh = r["refresh_token"] as? String ?? ""
            (status, data) = try await send()
        }
        guard (200..<300).contains(status) else {
            throw Failure(description: "\(method) \(path): \(status) \(String(decoding: data, as: UTF8.self))")
        }
        if data.isEmpty { return [:] }
        return (try JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
    }

    private func text(_ v: Any?) throws -> String {
        String(decoding: try JSONSerialization.data(withJSONObject: v ?? NSNull(), options: [.fragmentsAllowed]), as: UTF8.self)
    }

    /// A new account without a Secret Key, with its "Personal" vault.
    func register(email: String, password: String, name: String) async throws {
        let initRes = try await call("POST", "/auth/register/init", ["email": email])
        let created = try createAccount(accountId: initRes["account_id"] as! String, password: password, withSecretKey: false)
        let start = try opaqueRegisterStart(master: created.master)
        let resp = try await call("POST", "/auth/register/start", ["registration_id": initRes["registration_id"]!, "message": start.message])
        let upload = try opaqueRegisterFinish(state: start.state, master: created.master, response: resp["message"] as! String)
        let vaultId = try newId()
        let nv = try created.account.newVaultKey(vaultId: vaultId)
        try await call("POST", "/auth/register/finish", [
            "registration_id": initRes["registration_id"]!,
            "upload": upload,
            "bundle": try JSONSerialization.jsonObject(with: Data(created.bundleJson.utf8)),
            "name": name,
            "vault": ["id": vaultId, "meta": try nv.key.encryptMeta(vaultId: vaultId, metaJson: #"{"name":"Personal"}"#), "wrapped_key": nv.wrapped],
        ])
    }

    /// Sign in (with the authenticator code when two-step login is on).
    func login(email: String, password: String, totpSecret: String? = nil) async throws -> Session {
        let pre = try await call("POST", "/auth/prelogin", ["email": email])
        let master = try deriveMasterKeys(password: password, secretKey: nil, accountId: pre["account_id"] as! String, kdfJson: try text(pre["kdf"]), secretKeyRequired: false)
        let start = try opaqueLoginStart(master: master)
        let resp = try await call("POST", "/auth/login/start", ["email": email, "message": start.message])
        let fin = try opaqueLoginFinish(state: start.state, master: master, response: resp["message"] as! String)
        var result = try await call("POST", "/auth/login/finish", [
            "login_id": resp["login_id"]!, "message": fin,
            "device": ["id": UUID().uuidString.lowercased(), "name": "UI test helper", "kind": "mobile"],
        ])
        if result["two_factor_required"] as? Bool == true {
            guard let totpSecret else { throw Failure(description: "two-step login is on") }
            result = try await call("POST", "/auth/2fa/verify", [
                "two_factor_token": result["two_factor_token"]!, "provider": "totp", "code": try nextCode(totpSecret), "remember": false,
            ])
        }
        let account = try master.unlock(bundleJson: try text(result["bundle"]))
        return Session(email: email, account: account, access: result["access_token"] as! String, refresh: result["refresh_token"] as! String)
    }

    /// The current code, waiting for a fresh period first if less than 8 s are left
    /// (the server accepts each period's code once).
    func nextCode(_ secret: String) throws -> String {
        var c = try totpCode(secret: secret, unixSeconds: UInt64(Date().timeIntervalSince1970))
        if c.remaining < 8 {
            Thread.sleep(forTimeInterval: Double(c.remaining) + 1)
            c = try totpCode(secret: secret, unixSeconds: UInt64(Date().timeIntervalSince1970))
        }
        return c.code
    }

    /// Turn on authenticator two-step login; returns its secret. Waits for the next period
    /// before returning, so the code used here isn't the one the next sign-in needs.
    func enableTotp(_ s: Session) async throws -> String {
        let setup = try await call("POST", "/account/2fa/totp/setup", session: s)
        let secret = setup["secret"] as! String
        let c = try totpCode(secret: secret, unixSeconds: UInt64(Date().timeIntervalSince1970))
        try await call("POST", "/account/2fa/totp/enable", ["code": c.code], session: s)
        try await Task.sleep(nanoseconds: (UInt64(c.remaining) + 1) * 1_000_000_000)
        return secret
    }

    func createVault(_ s: Session, name: String) async throws {
        let id = try newId()
        let nv = try s.account.newVaultKey(vaultId: id)
        try await call("POST", "/vaults", ["id": id, "meta": try nv.key.encryptMeta(vaultId: id, metaJson: "{\"name\":\"\(name)\"}"), "wrapped_key": nv.wrapped], session: s)
    }

    /// Change an item (found by name) as another device would: decrypt, edit, re-encrypt, PUT
    /// with its revision.
    func editItem(_ s: Session, named name: String, _ change: (inout [String: Any]) -> Void) async throws {
        let sync = try await call("GET", "/sync", session: s)
        var keys: [String: VaultKey] = [:]
        for v in sync["vaults"] as? [[String: Any]] ?? [] {
            let id = v["id"] as! String
            keys[id] = try s.account.openVaultKey(vaultId: id, wrapped: v["wrapped_key"] as! String, kind: v["key_kind"] as! String)
        }
        for row in sync["items"] as? [[String: Any]] ?? [] where row["deleted_at"] == nil || row["deleted_at"] is NSNull {
            let vaultId = row["vault_id"] as! String
            guard let key = keys[vaultId] else { continue }
            let enc = EncryptedItem(id: row["id"] as! String, vaultId: vaultId, key: row["item_key"] as! String, data: row["data"] as! String)
            var item = try JSONSerialization.jsonObject(with: Data(try key.decryptItem(encrypted: enc).utf8)) as! [String: Any]
            guard item["name"] as? String == name else { continue }
            change(&item)
            let json = String(decoding: try JSONSerialization.data(withJSONObject: item), as: UTF8.self)
            let next = try key.updateItem(encrypted: enc, itemJson: json)
            try await call("PUT", "/items/\(enc.id)", ["id": next.id, "vault_id": next.vaultId, "key": next.key, "data": next.data, "revision": row["revision"]!], session: s)
            return
        }
        throw Failure(description: "no item named \(name)")
    }

    /// Create an item (item JSON in the web vault's format) in the account's own vault.
    func createItem(_ s: Session, _ item: [String: Any]) async throws {
        let sync = try await call("GET", "/sync", session: s)
        guard let v = (sync["vaults"] as? [[String: Any]])?.first(where: { $0["role"] as? String == "owner" }) else { throw Failure(description: "no vault") }
        let vaultId = v["id"] as! String
        let key = try s.account.openVaultKey(vaultId: vaultId, wrapped: v["wrapped_key"] as! String, kind: v["key_kind"] as! String)
        let json = String(decoding: try JSONSerialization.data(withJSONObject: item), as: UTF8.self)
        let enc = try key.encryptItem(itemJson: json, id: try newId(), vaultId: vaultId)
        try await call("POST", "/items", ["id": enc.id, "vault_id": enc.vaultId, "key": enc.key, "data": enc.data], session: s)
    }

    /// The account can't sign in any more (deleted).
    func accountExists(email: String, password: String) async -> Bool {
        (try? await login(email: email, password: password)) != nil
    }
}
