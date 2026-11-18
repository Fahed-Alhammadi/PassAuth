import Foundation
import PassAuthCore

// Signed sharing, the repository's side (docs/ARCHITECTURE.md "Signed sharing", "What the apps
// do"): who "me" is (the account id the core authenticated), the account's signing identity
// (made and uploaded at unlock when it has none, checked against the identity the key pins
// remember), the sealed key pins (`GET`/`PUT /account/key-pins` by compare-and-swap; the highest
// version this device opened stays in its memory, so an older list from the server is noticed),
// grandfathering at the first signed sync, member rosters fetched when newer than the remembered
// one (within caps), accepting and leaving, and key replacement (only from the state verified in
// the same sync, after a member review; version 1 only on the user's explicit confirmation). The
// checks themselves are in `SignedSharing.swift`.

/// A key replacement refused because the vault's members (or their roster, or its key) changed
/// after the list it was built from: synced and tried once more, then `text` is shown.
struct MembersChanged: Error {
    let text: String
}

/// More newer rosters than a device checks at once (1000 versions, 16 MiB per vault per sync).
struct RosterLimit: Error {}

extension VaultRepository {
    /// At most this many roster pages (100 versions each), and this much roster text, per vault
    /// and sync; beyond it the vault is refused rather than trusted on a partial chain.
    nonisolated static let maxRosterPages = 10
    nonisolated static let maxRosterVersions = 1000
    nonisolated static let maxRosterBytes = 16 << 20

    /// Whether signed sharing's checks run for the account: its server lists the feature, this
    /// device has trust memory for it (or can't read it just now), the copy carries anything signed
    /// (an identity, key pins, a share or a roster), or the server's features are unknown (never
    /// read) and its vault rows name key epochs. A server that stops listing the feature can't
    /// switch them off that way.
    func signedSharingOn(_ id: String, _ snapshot: SyncSnapshot? = nil, memory: SharingMemoryRecord? = nil) -> Bool {
        let features = store.get().file.accounts[id]?.features
        if features?.contains(signedSharingFeature) == true { return true }
        if !(memory ?? sharingMemory.load(id)).isEmpty { return true }
        guard let s = snapshot else { return false }
        if Self.showsSigning(s) { return true }
        // Unknown: run the checks (nothing that keeps them on is stored before the server shows it signs).
        return features == nil && s.vaults.contains { $0.keyEpoch != nil }
    }

    /// Whether a copy itself shows signed sharing (a listed identity, key pins, a share or a roster).
    nonisolated static func showsSigning(_ s: SyncSnapshot) -> Bool {
        if let identity = s.user?["identity"], case .object = identity { return true }
        if (s.user?["key_pins_seq"]?.number ?? 0) > 0 { return true }
        if s.vaults.contains(where: { ShareRecord.present($0.share) || $0.memberRoster != nil || ($0.memberRosterSeq ?? 0) > 0 }) { return true }
        return s.invitations.contains { ShareRecord.present($0.share) || $0.memberRoster != nil }
    }

    /// The copy shown now (the base of key replacement's checks), nil while locked.
    var copySnapshot: SyncSnapshot? { copyOf(activeId) }

    /// The active account's own identity fingerprint (computed from its unlocked signing key,
    /// never the server's); nil while locked, paused, or before it has a signing identity.
    public var ownIdentityFingerprint: String? {
        guard vault != nil else { return nil }
        return sessions[activeId]?.signing?.fingerprint()
    }

    /// This device's memory for the account, when it is this account's (the account id the core
    /// authenticated, on this server); another account's (after "Change server") starts empty.
    /// An unreadable one stays unreadable.
    func loadMemory(_ id: String, _ session: Session) -> SharingMemoryRecord {
        let server = store.get().file.accounts[id]?.server ?? ""
        let m = sharingMemory.load(id)
        return m.unreadable ? m : m.owned(by: session.meId, server: server)
    }

    /// Store the device memory: merged into what the other process (the app or its AutoFill
    /// extension) stored, its unsent key pins changes merged with ours (`pinsResolver`). false:
    /// not stored now (tried again with the next save).
    @discardableResult
    func saveMemory(_ id: String, _ session: Session, _ memory: SharingMemoryRecord) -> Bool {
        guard !memory.unreadable else { return false }
        return sharingMemory.save(id, memory, resolve: Self.pinsResolver(session.account))
    }

    /// When the stored sealed key pins and ours differ and either is a change not on the server
    /// yet, both are opened and merged (`merge_pins`: the unsent side's decisions on top of the
    /// other), so neither process's change is lost; the result is an unsent change on top of the
    /// higher server version. Otherwise (or when either can't be opened) ours as it is.
    nonisolated static func pinsResolver(_ account: Account) -> SharingMemoryResolver {
        { stored, ours in
            guard let a = stored.sealedPins, let b = ours.sealedPins, a != b, !stored.uploaded || !ours.uploaded,
                  stored.userId.isEmpty || ours.userId.isEmpty || stored.userId == ours.userId,
                  stored.server.isEmpty || ours.server.isEmpty || stored.server == ours.server,
                  let theirs = try? account.openKeyPins(sealed: a, seq: UInt64(stored.pinsSeq)),
                  let mine = try? account.openKeyPins(sealed: b, seq: UInt64(ours.pinsSeq)) else { return ours }
            // The side the server has (or the higher base) is the base; the unsent side goes on top.
            let oursOnTop = !ours.uploaded && (stored.uploaded || ours.serverBase >= stored.serverBase)
            let (base, top) = oursOnTop ? (theirs, mine) : (mine, theirs)
            guard let merged = try? mergePins(baseJson: base, oursJson: top) else { return ours }
            let seq = max(stored.serverBase, ours.serverBase) + 1
            guard let sealed = try? account.sealKeyPins(pinsJson: merged, seq: UInt64(seq)) else { return ours }
            var out = ours
            out.pinsSeq = seq
            out.sealedPins = sealed
            out.uploaded = false
            return out
        }
    }

    // MARK: Before decrypting a copy

    /// What the checks of `snapshot` need (step 0): "me", the key pins (the server's newer ones
    /// fetched, this device's last-known pins merged into them; rollback and withheld lists
    /// noticed), the signing identity (made and uploaded here when the account has none, the app
    /// only; tried again at every sync until the server answers) checked against the own identity
    /// the pins remember, the vaults grandfathered at the account's first signed sync
    /// (docs/ARCHITECTURE.md "Grandfathering" rules 1–4, cross-client rules 2 and 6), and the
    /// member rosters newer than the remembered ones (vaults and, the app only, invitations;
    /// within the caps). `network: false` (a copy from the device): nothing is asked of the
    /// server; a vault whose newer roster would be needed is refused as offline until the next
    /// sync. nil when signed sharing is off for the account. Throws for a copy of another account
    /// (`user.id` isn't this account's), and for a copy from the server while this device's
    /// memory can't be read and the server's key pins can't be had (treated as offline).
    func sharingInputs(_ id: String, _ session: Session, _ snapshot: inout SyncSnapshot, network: Bool) async throws -> SharingInputs? {
        var memory = loadMemory(id, session)
        guard signedSharingOn(id, snapshot, memory: memory) else { return nil }
        let meId = session.meId
        guard !meId.isEmpty else { return nil }
        if let listed = snapshot.user?["id"]?.string, !listed.isEmpty, listed != meId { throw UserError(SharingText.wrongAccount) }
        let features = store.get().file.accounts[id]?.features
        let featureListed = features?.contains(signedSharingFeature) == true
        let now = Int64(Date().timeIntervalSince1970)
        if memory.unreadable {
            return try await unreadableInputs(id, session, &snapshot, memory: memory, network: network, now: now)
        }
        let remembered = !memory.isEmpty
        let earlier = await earlierCopy(id, session)
        let prepared = await preparePins(id, session, snapshot, memory: &memory, network: network)
        var pins = prepared.pins
        var changed = prepared.changed
        let hadPins = pins != nil
        var ident = await prepareSigning(id, session, &snapshot, pins: &pins, changed: &changed, memory: &memory, network: network,
                                         mayCreate: prepared.unavailable == nil && !prepared.identityMismatch, ownBefore: prepared.deviceOwn,
                                         earlier: earlier)
        if prepared.identityMismatch {
            // Two own identities (round 5): merge nothing, write nothing, pause sharing.
            session.signingPaused = true
            ident.known = false
            ident.created = false
        }
        // Kept only once the server has shown it signs (rule 4): its config lists the feature (and
        // an identity upload wasn't answered 404), its answers carry signing, or this device
        // already has memory of it.
        let keep = remembered || Self.showsSigning(snapshot) || ident.created || prepared.fetched || (featureListed && !ident.unsupported)
        if keep && prepared.unavailable == nil { memory.proven = true }
        let sealedIds = snapshot.vaults.filter { !$0.keyKind.isEmpty && $0.keyKind != VaultInfo.accountKeyKind }.map(\.id)
        // The account's first signed sync (rules 1–3): only when the identity state is known, and
        // only the vault rows this device showed as usable before it generated the identity (the
        // candidates recorded then; none on a fresh install or a re-added account). The other
        // shared vaults wait for consent and may be accepted by the key shown, as when the
        // account's trust memory is missing (an identity exists but the server has no key pins
        // and this device remembers none).
        if network, keep, featureListed, prepared.unavailable == nil, ident.known, !session.signingPaused {
            if KeyPinsReader.field(pins, "grandfathered") == nil {
                let candidates = Set(memory.candidates ?? [])
                if !ident.created && !hadPins && memory.pinsSeq == 0 {
                    memory.missing = sealedIds
                    memory.missingDevice = false
                } else if ident.created {
                    memory.missing = sealedIds.filter { !candidates.contains($0) }
                    memory.missingDevice = true
                }
                // Each with the key it has now (round 5): a planted key under a grandfathered id
                // later needs consent.
                let account = session.account
                let pinsNow = pins
                let rows = ident.created ? snapshot.vaults.filter { candidates.contains($0.id) } : []
                let ids: [(vaultId: String, keyId: String)] = rows.compactMap { v in
                    let epoch = UInt64(max(0, v.keyEpoch ?? 0))
                    let legacy = (try? pinsLegacyWrapAllowed(pinsJson: pinsNow, vaultId: v.id, keyEpoch: epoch)) ?? true
                    guard let key = try? account.openVaultKey(vaultId: v.id, wrapped: v.wrappedKey, kind: v.keyKind,
                                                              keyEpoch: epoch, legacyAllowed: legacy),
                          let keyId = try? key.keyId(vaultId: v.id) else { return nil }
                    return (v.id, keyId)
                }
                if let next = try? pinsGrandfather(pinsJson: pins, vaultsJson: SignedSharing.candidatesJson(ids), createdIdentity: ident.created) {
                    pins = next
                    changed = true
                }
            } else if ident.created, memory.missing == nil {
                // Made here, but another device wrote the grandfathered list first (it didn't
                // make the identity, so it grandfathered nothing): this device's shared vaults
                // from before may be accepted by the key shown, without Decline (review M1 c).
                memory.missing = sealedIds
                memory.missingDevice = true
            }
        }
        let firstSyncDone = keep && prepared.unavailable == nil && ident.known && !session.signingPaused
            && KeyPinsReader.field(pins, "grandfathered") != nil
        // Declines whose key pins write failed before: written now with `pins_decline` (round 5,
        // iOS L): never for a vault the account holds (an epoch pin) or one of this sync's vault
        // rows, whatever its verdict, and always at roster version 0.
        let waiting = (memory.tombstones ?? [:]).merging(pendingTombstones[id] ?? [:]) { max($0, $1) }
        if network, keep, prepared.unavailable == nil, !session.signingPaused, !waiting.isEmpty {
            let rows = Set(snapshot.vaults.map(\.id))
            for vault in waiting.keys.sorted() {
                guard let next = try? pinsDecline(pinsJson: pins, vaultId: vault, currentRow: rows.contains(vault), now: now),
                      Self.pinsChanged(from: pins, to: next) else { continue }
                pins = next
                changed = true
            }
            memory.tombstones = [:]
            pendingTombstones[id] = nil
        }
        let notice: String? = if session.signingPaused {
            SharingText.paused
        } else if prepared.unavailable != nil {
            SharingText.pinsUnavailable
        } else if prepared.rolledBack {
            SharingText.pinsRolledBack
        } else if prepared.withheld {
            SharingText.pinsWithheld
        } else {
            nil
        }
        if network || session.signingPaused || prepared.unavailable != nil {
            sharingNotice = notice
        } else if sharingNotice == SharingText.paused {
            sharingNotice = nil
        }
        let (fetched, tooLarge) = prepared.unavailable == nil ? await fetchChains(id, snapshot, memory: memory, network: network) : ([:], [])
        var inputs = SharingInputs(me: sharingSelf(session), pins: pins, pinsChanged: changed, memory: memory, fetched: fetched, tooLarge: tooLarge,
                                   now: now)
        inputs.unavailable = prepared.unavailable
        // Without the key pins to check against, nothing is kept; a list the server withholds
        // isn't written over (this device's changes wait on it).
        inputs.keep = keep && prepared.unavailable == nil
        inputs.holdPins = prepared.withheld || prepared.identityMismatch
        inputs.notice = notice
        inputs.firstSyncDone = firstSyncDone
        session.sharingProven = inputs.keep
        if let pins { session.lastPins = pins }
        return inputs
    }

    /// The member rosters newer than the remembered ones, for the vaults and (the app only) the
    /// invitations whose head is `fetch` (within the caps; with the server only).
    private func fetchChains(_ id: String, _ snapshot: SyncSnapshot, memory: SharingMemoryRecord, network: Bool) async
        -> (fetched: [String: [String]], tooLarge: Set<String>) {
        var fetched: [String: [String]] = [:]
        var tooLarge = Set<String>()
        for v in snapshot.vaults {
            guard let h = SignedSharing.head(v.id, remembered: memory.rosters[v.id], latest: v.memberRoster), h.status == "fetch", network else { continue }
            do {
                fetched[v.id] = try await fetchRosters(id, vault: v.id, after: h.after)
            } catch is RosterLimit {
                tooLarge.insert(v.id)
            } catch {}
        }
        if isApp {
            for inv in snapshot.invitations where ShareRecord.present(inv.share) {
                guard let latest = inv.memberRoster,
                      let h = SignedSharing.head(inv.vaultId, remembered: memory.rosters[inv.vaultId], latest: latest), h.status == "fetch" else { continue }
                let cacheKey = "\(h.after)\n\(latest)"
                if let known = invitationChains[inv.vaultId], known.latest == cacheKey {
                    fetched[inv.vaultId] = known.chain
                } else if network {
                    do {
                        let list = try await fetchRosters(id, vault: inv.vaultId, after: h.after)
                        invitationChains[inv.vaultId] = (cacheKey, list)
                        fetched[inv.vaultId] = list
                    } catch is RosterLimit {
                        tooLarge.insert(inv.vaultId)
                    } catch {}
                }
            }
        }
        return (fetched, tooLarge)
    }

    /// This device's memory can't be read just now (review L3): nothing is made, grandfathered or
    /// written, every shared vault is refused, and the account's own vaults are still checked
    /// against key pins, never against none: the pins this unlock already had, else (a copy from
    /// the server) the server's, opened read-only. A copy from the server whose key pins can't be
    /// had is treated as offline (throws; the copy shown stays).
    private func unreadableInputs(_ id: String, _ session: Session, _ snapshot: inout SyncSnapshot, memory: SharingMemoryRecord, network: Bool,
                                  now: Int64) async throws -> SharingInputs {
        var memory = memory
        var pins = session.lastPins
        let serverSeq = snapshot.user?["key_pins_seq"]?.number ?? 0
        if network, serverSeq > 0 {
            let account = session.account
            if let j = try? await api.call(id, "/account/key-pins"), let seq = j["seq"]?.number, seq >= 0, let sealed = j["key_pins"]?.string,
               let opened = try? await core({ try account.openKeyPins(sealed: sealed, seq: UInt64(seq)) }) {
                // Read only: the device's last-known pins merged into the server's (round 5 M1);
                // another own identity → only this unlock's.
                pins = pins.map { (try? pinsMergeLastKnown(serverJson: opened, lastKnownJson: $0)) ?? $0 } ?? opened
            }
        }
        // The account has key pins (the copy says so) but none can be had: not used (as offline).
        if pins == nil, serverSeq > 0 { throw UserError(SharingText.memoryUnreadable) }
        var changed = false
        var scratch = pins
        _ = await prepareSigning(id, session, &snapshot, pins: &scratch, changed: &changed, memory: &memory, network: false, mayCreate: false,
                                 ownBefore: nil, earlier: nil)
        var inputs = SharingInputs(me: sharingSelf(session), pins: pins, pinsChanged: false, memory: memory, fetched: [:], tooLarge: [], now: now)
        inputs.unavailable = "memory_unreadable"
        inputs.keep = false
        inputs.notice = SharingText.memoryUnreadable
        sharingNotice = SharingText.memoryUnreadable
        return inputs
    }

    /// Who this account is to the checks.
    func sharingSelf(_ session: Session) -> SharingSelf {
        let signing = session.signing
        let identity = (try? signing?.publicIdentityJson()) ?? (try? session.account.legacyIdentityJson()) ?? ""
        return SharingSelf(identity: identity, userId: session.meId, signingHash: signing?.identityHash(), paused: session.signingPaused)
    }

    /// The vaults this device showed as usable before this unlock (rule 1, cross-client rule 6):
    /// the device memory's `seen` list as it was when this unlock started (read once per unlock).
    /// An app from before kept no such list: then the vault ids of the account's offline copy on
    /// this device (written by that app, which didn't check). nil without either (a fresh
    /// install, a re-added account) or when the copy is another account's.
    func earlierCopy(_ id: String, _ session: Session, given: SyncSnapshot? = nil) async -> Set<String>? {
        if session.earlierCopyRead { return session.earlierCopy }
        session.earlierCopyRead = true
        let memory = sharingMemory.load(id)
        if memory.unreadable { return nil }
        let server = store.get().file.accounts[id]?.server ?? ""
        let mine = memory.owned(by: session.meId, server: server)
        if mine.unreadable { return nil }
        if let seen = mine.seen, mine.userId == memory.userId || memory.userId.isEmpty {
            session.earlierCopy = Set(seen)
            return session.earlierCopy
        }
        // The offline copy (which a background refresh may have written while locked) stands in
        // only for an app from before that kept no device memory at all (round 5, iOS H): once
        // any record exists, its `seen` list (or none) is the earlier copy.
        if !memory.isEmpty || memory.seen != nil || memory.candidates != nil || !memory.userId.isEmpty { return nil }
        let copy: SyncSnapshot?
        if let given { copy = given } else { copy = await readSnapshot(id) }
        guard let copy else { return nil }
        if let listed = copy.user?["id"]?.string, !listed.isEmpty, listed != session.meId { return nil }
        session.earlierCopy = Set(copy.vaults.map(\.id))
        return session.earlierCopy
    }

    /// Remember the vaults this device just showed as usable (the foreground only; cross-client
    /// rule 6). Written only when the list grows; never turns the checks on.
    func recordSeen(_ id: String, _ session: Session, _ ids: [String]) {
        guard !ids.isEmpty else { return }
        let memory = loadMemory(id, session)
        guard !memory.unreadable else { return }
        let have = Set(memory.seen ?? [])
        guard memory.seen == nil || !Set(ids).isSubset(of: have) else { return }
        var update = SharingMemoryRecord().owned(by: session.meId, server: memory.server)
        update.userId = memory.userId
        update.seen = ids
        saveMemory(id, session, update)
    }

    /// The signing identity as far as one sync tells.
    struct IdentityState {
        /// The state is known (a listed identity opened, or one made now and stored): only then is
        /// grandfathering written (rule 2).
        var known = false
        /// This device made it: now (`created: true`), or by an upload whose answer was lost (the
        /// listed record opens to the hash it kept before uploading; rule 3).
        var created = false
        /// The upload was answered 404: this server doesn't sign.
        var unsupported = false
    }

    /// The signing identity (step 0): the record `/sync` lists (`user.identity`) opened with this
    /// account's key, once per record, and checked against the own identity the key pins remember
    /// (`pins_check_own_identity`: `new` is remembered now). None listed while the pins remember
    /// one, a record this account's key doesn't open, a malformed record, or another identity than
    /// the remembered one: sharing is **paused** (nothing signed, every shared vault refused). None
    /// listed and none remembered: the app makes one (or takes the one it made before, kept in the
    /// device memory before uploading) and uploads it (`PUT /account/identity`); only `created:
    /// true` counts as made now. On 409 `identity_exists` the copy is fetched again and the stored
    /// one opened, with the state unknown for this sync (nothing grandfathered).
    ///
    /// `ownBefore`: the own identity this device's pins remembered before this sync (an identity
    /// generated here counts as made here only when there was none); `earlier`: the vaults this
    /// device showed as usable before this unlock (recorded as the grandfathering candidates when
    /// an identity is generated). The upload is tried again at every sync until the server
    /// answers it (`created`, 404 or 409).
    func prepareSigning(_ id: String, _ session: Session, _ snapshot: inout SyncSnapshot, pins: inout String?, changed: inout Bool,
                        memory: inout SharingMemoryRecord, network: Bool, mayCreate: Bool, ownBefore: String?,
                        earlier: Set<String>?) async -> IdentityState {
        let account = session.account
        var paused = false
        var hash: String?
        var state = IdentityState()
        switch snapshot.user?["identity"] {
        case .object?:
            let record = snapshot.user?["identity"] ?? .null
            if session.signingRecord != record {
                session.signingRecord = record
                let text = record.text
                session.openedSigning = try? await core { try account.openSigningIdentity(recordJson: text) }
            }
            if let s = session.openedSigning {
                hash = s.identityHash()
                state.known = true
                // Generated here (kept before uploading; the answer may have been lost) counts
                // only while no own identity was known here before (review L2).
                state.created = session.identityCreated
                    || (memory.pendingIdentity != nil && memory.pendingIdentity == hash && !memory.settled && ownBefore == nil)
            } else {
                paused = true
            }
        case nil, .null?:
            if session.identityTried, session.signingRecord != nil, let s = session.openedSigning {
                // Made by this unlock; the copy predates it.
                hash = s.identityHash()
                state.known = session.identityCreated
                state.created = session.identityCreated
            } else if (try? pinsCheckOwnIdentity(pinsJson: pins, listed: nil)) == "mismatch" {
                // The pins remember an identity the server no longer lists: a rollback.
                paused = true
            } else if network, isApp, mayCreate, !session.identityTried,
                      store.get().file.accounts[id]?.features?.contains(signedSharingFeature) == true {
                if let made = await madeIdentity(id, session, memory: &memory, earlier: earlier) {
                    do {
                        let answer = try await api.call(id, "/account/identity", body: made.record, method: "PUT")
                        // Answered: not sent again by this unlock; the server signs.
                        session.identityTried = true
                        memory.proven = true
                        if answer["created"]?.bool == true {
                            session.openedSigning = made.identity
                            session.signingRecord = made.record
                            session.identityCreated = true
                            hash = made.identity.identityHash()
                            state = IdentityState(known: true, created: true)
                            if case .object(var u)? = snapshot.user {
                                u["identity"] = made.record
                                snapshot.user = .object(u)
                            }
                        }
                        // Any other answer: the state stays unknown; the next sync lists what the
                        // server stored (the kept hash tells whether it is this one).
                    } catch let e as ApiError where e.status == 409 && e.hasCode("identity_exists") {
                        // Another device made one meanwhile: open the stored one. Grandfathering
                        // waits for the next sync (rule 3).
                        session.identityTried = true
                        memory.proven = true
                        if let fresh = try? await fetchSnapshot(id), case .object? = fresh.user?["identity"] {
                            snapshot = fresh
                            var other = memory
                            _ = await prepareSigning(id, session, &snapshot, pins: &pins, changed: &changed, memory: &other, network: false,
                                                     mayCreate: false, ownBefore: ownBefore, earlier: nil)
                            return IdentityState()
                        }
                    } catch let e as ApiError where e.status == 404 {
                        session.identityTried = true
                        state.unsupported = true
                    } catch {
                        // Not answered (offline, 5xx, a refused request): tried again at the next
                        // sync, with the same identity (review M1 b).
                    }
                }
            }
        default:
            paused = true
        }
        if !paused, let hash {
            switch try? pinsCheckOwnIdentity(pinsJson: pins, listed: hash) {
            case "new"?:
                if let next = try? pinsSetOwnIdentity(pinsJson: pins, hash: hash) {
                    pins = next
                    changed = true
                }
            case "match"?: break
            default: paused = true
            }
        }
        session.signingPaused = paused
        if paused { state.known = false }
        return state
    }

    /// The signing identity to upload: the one this device made before (its record kept in the
    /// device memory, so an upload tried again sends the same one), else a new one, kept there
    /// first. nil when it can't be kept (then it isn't uploaded).
    /// The candidates for grandfathering are recorded with it, once (`earlier`, the vaults this
    /// device showed as usable before this unlock; review L2).
    private func madeIdentity(_ id: String, _ session: Session, memory: inout SharingMemoryRecord,
                              earlier: Set<String>?) async -> (identity: SigningIdentity, record: JSON)? {
        let account = session.account
        if let text = memory.pendingRecord, let record = try? JSON.parse(text),
           let s = try? await core({ try account.openSigningIdentity(recordJson: text) }), s.identityHash() == memory.pendingIdentity {
            return (s, record)
        }
        guard let made = try? await core({ try account.newSigningIdentity() }), let record = try? JSON.parse(made.recordJson) else { return nil }
        memory.pendingIdentity = made.identity.identityHash()
        memory.pendingRecord = made.recordJson
        if memory.candidates == nil { memory.candidates = (earlier ?? []).sorted() }
        // Not `proven` yet: only an answer other than 404 shows the server signs (round 5 Info).
        guard saveMemory(id, session, memory) else { return nil }
        return (made.identity, record)
    }

    /// What `preparePins` found.
    struct PreparedPins {
        /// The key pins to check with (JSON; nil: none yet).
        var pins: String?
        /// They differ from the stored ones (this device's changes merged into the server's).
        var changed = false
        /// The server sent an older version than this device opened: the device's list stays.
        var rolledBack = false
        /// The server lists a newer version than this device's but didn't give it (or it doesn't
        /// open): the device's list stays and the app says so.
        var withheld = false
        /// The same on a device without a list of its own: every shared vault is refused
        /// (`pins_unavailable`) until the list can be had; nothing is grandfathered or made.
        var unavailable: String?
        /// `GET /account/key-pins` answered (the server signs).
        var fetched = false
        /// The own identity this device's pins remembered before this sync (nil: none).
        var deviceOwn: String?
        /// The server's newer pins remember another own identity than this device's (round 5):
        /// nothing merged or written, sharing paused.
        var identityMismatch = false
    }

    /// The key pins to check with. With the server: a newer list (`user.key_pins_seq` above what
    /// this device has) is fetched and opened, and this device's own changes not stored yet are
    /// merged into it (written by `finishSharing`). A version below the one this device opened is
    /// a rollback, a newer one that can't be had is withheld: the device's list stays (or, without
    /// one, shared vaults wait).
    func preparePins(_ id: String, _ session: Session, _ snapshot: SyncSnapshot, memory: inout SharingMemoryRecord,
                     network: Bool) async -> PreparedPins {
        let account = session.account
        var out = PreparedPins()
        if let sealed = memory.sealedPins {
            let seq = UInt64(memory.pinsSeq)
            out.pins = try? await core { try account.openKeyPins(sealed: sealed, seq: seq) }
            if out.pins == nil {
                // Unreadable on this device: start from the server's.
                memory.sealedPins = nil
                memory.pinsSeq = 0
                memory.uploaded = true
            }
        }
        out.deviceOwn = KeyPinsReader.field(out.pins, "own_identity")?.string
        let serverSeq = snapshot.user?["key_pins_seq"]?.number ?? 0
        // The server's newer list can't be had: keep the device's, or (none) wait for it.
        func missingNewer() -> PreparedPins {
            var o = out
            if o.pins != nil { o.withheld = true } else { o.unavailable = "pins_unavailable" }
            return o
        }
        guard network else {
            // Offline: a device without a list of its own can't check against the server's.
            return out.pins == nil && serverSeq > 0 ? missingNewer() : out
        }
        if serverSeq < memory.serverBase {
            out.rolledBack = true
            return out
        }
        guard serverSeq > memory.serverBase || (out.pins == nil && serverSeq > 0) else { return out }
        guard let j = try? await api.call(id, "/account/key-pins") else { return missingNewer() }
        out.fetched = true
        guard let seq = j["seq"]?.number else { return missingNewer() }
        if seq < memory.serverBase {
            out.rolledBack = true
            return out
        }
        guard let sealed = j["key_pins"]?.string,
              let opened = try? await core({ try account.openKeyPins(sealed: sealed, seq: UInt64(seq)) }) else {
            // None (or unreadable) while the server's own `/sync` says there is a newer version.
            return seq > 0 || serverSeq > 0 ? missingNewer() : out
        }
        let ours = out.pins
        // This device's pins merged into every newer server copy (cross-client rule 5), not only
        // with unsent changes: unsent changes on top (`merge_pins`, this device's decision wins);
        // otherwise its last-known pins with `pins_merge_last_known` (round 5 M1: only what never
        // goes back, the server's copy wins for people pinned with another identity, so two
        // devices don't rewrite each other's pins in a loop). Written back (`finishSharing`) only
        // when the merge adds anything. Another own identity on either side (`identity_mismatch`):
        // nothing merged or written, the device's copy stays, sharing paused.
        var merged = opened
        if let ours {
            do {
                merged = memory.uploaded ? try pinsMergeLastKnown(serverJson: opened, lastKnownJson: ours)
                    : try mergePins(baseJson: opened, oursJson: ours)
            } catch let e as CoreError {
                if case .IdentityMismatch = e {
                    out.identityMismatch = true
                    return out
                }
                // Unmergeable otherwise: keep the device's list (as withheld).
                out.withheld = true
                return out
            } catch {
                out.withheld = true
                return out
            }
        }
        memory.pinsSeq = seq
        memory.sealedPins = sealed
        memory.uploaded = true
        out.pins = opened
        if !Self.samePins(merged, opened) {
            out.pins = merged
            out.changed = true
        }
        return out
    }

    /// Whether two key pins (JSON) say the same, apart from their version.
    nonisolated static func samePins(_ a: String, _ b: String) -> Bool {
        guard case .object(var x)? = try? JSON.parse(a), case .object(var y)? = try? JSON.parse(b) else { return a == b }
        x["version"] = nil
        y["version"] = nil
        return JSON.object(x) == JSON.object(y)
    }

    /// `GET /vaults/{id}/rosters?after=N`, page after page: every roster version after `after`,
    /// oldest first, at most `maxRosterVersions` versions in `maxRosterPages` pages and
    /// `maxRosterBytes` of text (`RosterLimit` beyond; a page larger than what is left of it is
    /// refused before it is parsed).
    func fetchRosters(_ id: String, vault: String, after: Int64) async throws -> [String] {
        var out: [String] = []
        var bytes = 0
        var after = after
        for _ in 0..<Self.maxRosterPages {
            let data = try await api.callData(id, "/vaults/\(Self.pathPart(vault))/rosters?after=\(after)")
            // JSON escaping can only make a page longer than its rosters' text: a page beyond the
            // rest of the budget (plus room for the envelope) can't fit.
            if data.count > Self.maxRosterBytes - bytes + 64 * 1024 { throw RosterLimit() }
            guard let j = try? JSON.parse(data), case .array(let list)? = j["rosters"] else { throw DeltaSync.unreadable }
            let page = list.compactMap(\.string)
            guard page.count == list.count else { throw DeltaSync.unreadable }
            out += page
            bytes += page.reduce(0) { $0 + $1.utf8.count }
            if bytes > Self.maxRosterBytes || out.count > Self.maxRosterVersions { throw RosterLimit() }
            if j["more"]?.bool != true || page.isEmpty { return out }
            let last = page.last.flatMap(SignedSharing.rosterVersion).map { Int64($0) } ?? (after + Int64(page.count))
            guard last > after else { throw DeltaSync.unreadable }
            after = last
        }
        throw RosterLimit()
    }

    // MARK: After decrypting a copy

    /// Keep what the checks changed: the device memory (merged with what the other process
    /// stored), and the key pins written (compare-and-swap) when they changed or this device still
    /// has changes the server lacks. Nothing is kept before the server has shown it signs
    /// (`keep`). The notice says when shared vaults wait for consent because the account's trust
    /// memory was missing or this device had no earlier copy of them.
    func finishSharing(_ id: String, _ session: Session, _ out: SharingOutputs, network: Bool) async {
        var memory = out.memory
        var pins = out.pins
        if out.keep && !memory.unreadable {
            if let p = pins, network, !out.holdPins, out.pinsChanged || !memory.uploaded {
                pins = await writePins(id, session, p, memory: &memory)
            } else if out.pinsChanged || memory.sealedPins == nil, let p = pins {
                // Offline: kept on the device and written at the next sync.
                sealOnDevice(session, p, memory: &memory)
            }
            // The key pins on the server remember the own identity and the grandfathered list: the
            // pending identity and the grandfathering candidates are done with (review L2).
            if memory.uploaded, KeyPinsReader.field(pins, "own_identity") != nil, KeyPinsReader.field(pins, "grandfathered") != nil {
                memory.settled = true
                memory.pendingIdentity = nil
                memory.pendingRecord = nil
                memory.candidates = nil
            }
            saveMemory(id, session, memory)
        }
        if let pins { session.lastPins = pins }
        guard activeId == id else { return }
        knownPeople = KeyPinsReader.people(pins)
        guard out.notice == nil else { return }
        if !(memory.missing ?? []).isEmpty {
            sharingNotice = memory.missingDevice ? SharingText.newDevice : SharingText.trustMemoryMissing
        } else if sharingNotice == SharingText.newDevice || sharingNotice == SharingText.trustMemoryMissing {
            sharingNotice = nil
        }
    }

    /// Keep `pins` on the device as this device's change on top of the server's version.
    private func sealOnDevice(_ session: Session, _ pins: String, memory: inout SharingMemoryRecord) {
        let seq = memory.serverBase + 1
        guard let sealed = try? session.account.sealKeyPins(pinsJson: pins, seq: UInt64(seq)) else { return }
        memory.pinsSeq = seq
        memory.sealedPins = sealed
        memory.uploaded = false
    }

    /// `PUT /account/key-pins` as the next version of the server's; on 409 `key_pins_changed` the
    /// newer list is fetched, this device's pins merged into it, and written once more. Not
    /// written: kept on the device, for the next sync. Returns the pins as written (merged).
    @discardableResult
    func writePins(_ id: String, _ session: Session, _ pins: String, memory: inout SharingMemoryRecord) async -> String {
        let account = session.account
        var current = pins
        for attempt in 0..<2 {
            sealOnDevice(session, current, memory: &memory)
            guard let sealed = memory.sealedPins else { return current }
            do {
                _ = try await api.call(id, "/account/key-pins", body: ["key_pins": .string(sealed), "seq": .int(memory.pinsSeq)], method: "PUT")
                memory.uploaded = true
                return current
            } catch let e as ApiError where e.status == 409 && e.hasCode("key_pins_changed") && attempt == 0 {
                guard let j = try? await api.call(id, "/account/key-pins"), let seq = j["seq"]?.number, seq >= memory.serverBase,
                      let s = j["key_pins"]?.string,
                      let opened = try? await core({ try account.openKeyPins(sealed: s, seq: UInt64(seq)) }),
                      let merged = try? mergePins(baseJson: opened, oursJson: current) else { return current }
                current = merged
                memory.pinsSeq = seq
                memory.sealedPins = s
                memory.uploaded = true
            } catch {
                return current
            }
        }
        return current
    }

    /// The account's key pins as this device has them (no server request), and its memory.
    func devicePins(_ id: String, _ session: Session) -> (String?, SharingMemoryRecord) {
        let memory = loadMemory(id, session)
        let pins = memory.sealedPins.flatMap { try? session.account.openKeyPins(sealed: $0, seq: UInt64(memory.pinsSeq)) }
        return (pins, memory)
    }

    /// Change the account's key pins (`change` returns nil: nothing to change) and write them;
    /// not written (offline, conflict twice) they stay on the device for the next sync. The
    /// caller holds the repository's lock. Throws when this device's memory can't be read now
    /// (nothing is written over it) or the change couldn't be kept anywhere.
    ///
    /// Nothing is written before the server has shown it signs (cross-client rule 2): a decision
    /// written on a server that doesn't sign would keep the checks on for good.
    func updatePins(_ id: String, _ session: Session, _ change: (String?) throws -> String?) async throws {
        var (pins, memory) = devicePins(id, session)
        if memory.unreadable { throw UserError(SharingText.memoryUnreadable) }
        guard memory.proven || session.sharingProven else { throw UserError(SharingText.checking) }
        guard let next = try change(pins) else { return }
        pins = await writePins(id, session, next, memory: &memory)
        if !memory.uploaded, let p = pins { sealOnDevice(session, p, memory: &memory) }
        let kept = saveMemory(id, session, memory)
        if activeId == id { knownPeople = KeyPinsReader.people(pins) }
        if !kept && !memory.uploaded { throw UserError(SharingText.memoryUnreadable) }
    }

    /// Whether a vault has signed history on this device or account (emergency access counts it
    /// as personal only without): a trusted roster listing anyone else, a share seen signed, or an
    /// epoch pin with `signed_since`. Unknown (locked, or the memory can't be read): true.
    func hasSignedHistory(_ vaultId: String) -> Bool {
        let id = activeId
        guard let session = sessions[id] else { return true }
        let (pins, memory) = devicePins(id, session)
        if memory.unreadable { return true }
        if memory.signed.contains(vaultId) || KeyPinsReader.signedSince(pins, vaultId) { return true }
        if let roster = memory.rosters[vaultId], SignedSharing.rosterMembers(roster) != [session.meId] { return true }
        return false
    }

    // MARK: Decisions

    /// "Trust the new key": pin the signer's new identity with exactly the email the sheet shows
    /// (`SignerInfo.trustEmail`; `compared`: the user compared its fingerprint with them, so it is
    /// marked verified), write the key pins, sync (the vault or invitation is checked again). Not
    /// for an email pinned under another account.
    public func trustNewKey(_ signer: SignerInfo, compared: Bool) async throws {
        guard signer.pin != .emailConflict else { throw UserError(SharingText.keyChanged(signer)) }
        try await lock.run {
            let id = activeId
            guard vault != nil, let session = sessions[id] else { throw UserError("Unlock your vault first.") }
            let email = signer.trustEmail
            try await updatePins(id, session) { pins in
                try pinSet(pinsJson: pins, identityJson: signer.identity, email: email, verified: compared, now: Int64(Date().timeIntervalSince1970))
            }
            try? await syncLocked()
        }
    }

    /// "Mark as verified" after comparing a pinned person's fingerprint out of band: only while the
    /// pinned identity still is the one shown (else "keys changed; compare again").
    public func markVerified(_ person: PinnedPerson) async throws {
        try await lock.run {
            let id = activeId
            guard vault != nil, let session = sessions[id] else { throw UserError("Unlock your vault first.") }
            try await updatePins(id, session) { pins in
                guard let next = try KeyPinsReader.markingVerified(pins, userId: person.userId, identityHash: person.identityHash) else {
                    throw UserError("This person isn't in your list of known keys any more.")
                }
                return next
            }
        }
    }

    /// Accepting a verified invitation, or a vault the server added (step 3, consent): pin its
    /// signer (still the identity checked) with exactly the email the user was shown, then
    /// `pins_accept` with the observation the checks admitted (the key, the roster's version and
    /// hash, the chain fetched for it; clears a tombstone, marks the re-join), then remember its
    /// verified roster. The caller holds the lock.
    func accept(_ id: String, _ session: Session, vaultId: String, _ a: Acceptance) async throws {
        let now = Int64(Date().timeIntervalSince1970)
        let observation = a.observation(vaultId: vaultId, paused: session.signingPaused)
        try await updatePins(id, session) { pins in
            var p = pins
            if let s = a.signer {
                switch try pinCheck(pinsJson: p, identityJson: s.identity, email: s.pinEmailToWrite) {
                case "changed", "email_conflict": throw UserError(SharingText.keyChanged(s))
                case "match": break
                default: p = try pinSet(pinsJson: p, identityJson: s.identity, email: s.pinEmailToWrite, verified: s.pinVerifiedToWrite, now: now)
                }
            }
            do {
                return try pinsAccept(pinsJson: p, observationJson: observation)
            } catch let e as CoreError {
                if case .IdentityMismatch = e { throw UserError(SharingText.paused) }
                throw UserError(SharingText.refused)
            }
        }
        var memory = loadMemory(id, session)
        if let roster = a.roster { memory.rosters[vaultId] = roster }
        if a.roster != nil, !memory.signed.contains(vaultId) { memory.signed.append(vaultId) }
        if let m = memory.missing, m.contains(vaultId) { memory.missing = m.filter { $0 != vaultId } }
        saveMemory(id, session, memory)
    }

    /// Declining an invitation or a vault the server added (round 5 M2, `pins_decline`): a
    /// tombstone at roster version 0, and only for a vault the account doesn't hold (no epoch
    /// pin), hasn't left already and that isn't one of this sync's vault rows (`currentRow`,
    /// whatever its verdict); otherwise nothing changes. A server-chosen roster version never
    /// goes into a tombstone. The caller holds the lock.
    func decline(_ id: String, _ session: Session, vaultId: String, currentRow: Bool) async throws {
        let now = Int64(Date().timeIntervalSince1970)
        try await updatePins(id, session) { pins in
            let next = try pinsDecline(pinsJson: pins, vaultId: vaultId, currentRow: currentRow, now: now)
            return Self.pinsChanged(from: pins, to: next) ? next : nil
        }
    }

    /// Whether `next` says something `pins` (nil: none yet) doesn't: an empty list made from none
    /// isn't a change.
    nonisolated static func pinsChanged(from pins: String?, to next: String) -> Bool {
        if let pins { return !samePins(next, pins) }
        guard case .object(let o)? = try? JSON.parse(next) else { return true }
        return o.contains { key, value in
            switch (key, value) {
            case ("version", _), (_, .null): false
            case (_, .array(let a)): !a.isEmpty
            case (_, .object(let m)): !m.isEmpty
            default: true
            }
        }
    }

    /// After this device's own key replacement was accepted (step 5): the new key recorded in
    /// the account's key pins (`pins_record_rotation`, round 5; the roster it signed with its
    /// hash, or neither), kept on the device as an unsent change until written. Best effort:
    /// the next sync observes the account's own row anyway.
    func recordOwnRotation(_ id: String, _ session: Session, vaultId: String, epochPin: String, roster: String?) async {
        guard signedSharingOn(id, copySnapshot) else { return }
        let version = roster.flatMap(SignedSharing.rosterVersion)
        let hash = roster.flatMap { try? rosterHash(rosterJson: $0) }
        guard (version == nil) == (hash == nil) else { return }
        try? await updatePins(id, session) { pins in
            try pinsRecordRotation(pinsJson: pins, vaultId: vaultId, keyKind: VaultInfo.accountKeyKind, currentJson: epochPin,
                                   rosterVersion: version, rosterHash: hash)
        }
    }

    // MARK: Key replacement

    /// A member row of `GET /vaults/{id}/members`.
    struct MemberRow {
        let userId: String
        /// The email the server lists, as pins keep it (cleaned).
        let email: String
        let role: String
        /// As the core reads it.
        let identity: String
    }

    nonisolated static func memberRows(_ answer: JSON) -> [MemberRow]? {
        guard case .array(let list)? = answer["members"] else { return nil }
        var out: [MemberRow] = []
        for m in list {
            guard let identity = SharingIdentity.json(m), let role = m["role"]?.string, !role.isEmpty else { return nil }
            out.append(MemberRow(userId: m.str("user_id"), email: SharingIdentity.pinEmail(m.str("email")), role: role, identity: identity))
        }
        return out
    }

    /// Replace a vault's key with signed sharing on (step 5), only from the state verified in this
    /// same sync (`row`: the vault's row whose checks passed, its roster the trusted one) and only
    /// with the members answer that decides everything (`members`, `answer`: its key epoch and
    /// roster must be the verified ones). `personalOnly` (emergency access): replaced only when
    /// that same answer says the vault is personal (owned, account key, the user alone, no signed
    /// history), else `.shared`. No trusted roster and the user alone: replaced unsigned, sealed to
    /// nobody. Otherwise the member review (`roster_review`): blocked → stop; no trusted roster →
    /// the version-1 review the user confirms (`reviewed` = the digest they confirmed; never
    /// automatic); members added or changed against the trusted roster → stop; members the roster
    /// lists but the server doesn't → confirmed per user id (`confirmed`). Then a new key, wrapped
    /// for this account, sealed and signed for everyone else at the next epoch, every item
    /// re-encrypted with its revision, and the next roster signed over the reviewed list.
    func rotateSigned(_ id: String, _ session: Session, _ info: VaultInfo, row: SyncVault?, oldKey: VaultKey, rows: [SyncItem], answer: JSON,
                      members: [MemberRow], confirmed: Set<String>, reviewed: String?, personalOnly: Bool) async throws -> RotationOutcome {
        let vid = info.id
        let me = session.meId
        let unverified = UserError("PassAuth couldn't verify this vault's signed member list, so it didn't change the key. Ask its owner, or your server's admin.")
        let moved = MembersChanged(text: "This vault's members or key changed while PassAuth checked them. Try again.")
        guard let row, let epoch = info.keyEpoch, row.keyEpoch == epoch else { throw unverified }
        // The answer must describe the state this sync verified (its key epoch and roster).
        let trusted = row.memberRoster
        let seq = answer["member_roster_seq"]?.number ?? 0
        guard answer["key_epoch"]?.number == epoch else { throw moved }
        guard answer["member_roster"]?.string == trusted, seq == Int64(trusted.flatMap(SignedSharing.rosterVersion) ?? 0) else { throw moved }
        if let t = trusted {
            guard SignedSharing.rosterEpoch(t) == epoch, (try? oldKey.matchesRoster(vaultId: vid, rosterJson: t)) == true else { throw unverified }
        }
        let onlyMe = members.map(\.userId) == [me]
        let (pins, memory) = devicePins(id, session)
        // Never reviewed without the account's key pins (review L3).
        if memory.unreadable { throw UserError(SharingText.memoryUnreadable) }
        if personalOnly {
            let personal = onlyMe && info.keyKind == VaultInfo.accountKeyKind && info.role == .owner
                && (trusted.map { SignedSharing.rosterMembers($0) == [me] } ?? true)
                && !memory.signed.contains(vid) && !KeyPinsReader.signedSince(pins, vid)
            guard personal else { return .shared(info.name) }
        }
        if trusted == nil && onlyMe { return try await rotatePlain(id, session, info, oldKey: oldKey, rows: rows) }
        guard let signing = session.signing else { throw UserError(session.signingPaused ? SharingText.paused : SharingText.needsIdentity) }
        let myPub = try signing.publicIdentityJson()
        let inputs = members.compactMap { SharingIdentity.memberJson($0.identity, role: $0.role, email: $0.email) }
        guard inputs.count == members.count else { throw unverified }
        let membersJson = JSON.array(inputs).text
        let review: MemberReview
        do {
            guard let r = MemberReview.read(try rosterReview(vaultId: vid, previous: trusted, signerJson: myPub, membersJson: membersJson, pinsJson: pins))
            else { throw unverified }
            review = r
        } catch let e as CoreError {
            if case .RosterUnauthorized = e { throw UserError("You can't change this vault's members. Ask its owner.") }
            throw unverified
        }
        if review.blocked {
            let blockers = review.blockers
            if let keyChanged = blockers.first(where: { $0.pin == "changed" || $0.pin == "email_conflict" }) {
                throw UserError(SharingText.memberKeyChanged(keyChanged.shownEmail))
            }
            throw UserError(SharingText.membersDiffer((blockers.isEmpty ? review.members : blockers).map(\.shownEmail)))
        }
        if review.first {
            // Version 1: only what the user saw and confirmed is signed and sealed to; the emails
            // shown are kept with the digest (people seen for the first time are pinned with them).
            guard reviewed == review.digest, reviewedEmails[vid]?[review.digest] != nil else {
                var shown = reviewedEmails[vid] ?? [:]
                if shown.count >= 8 { shown = [:] }
                shown[review.digest] = Dictionary(members.map { ($0.userId, $0.email) }, uniquingKeysWith: { a, _ in a })
                reviewedEmails[vid] = shown
                return .review(info.name, review)
            }
        } else {
            let changed = review.changed
            if !changed.isEmpty { throw UserError(SharingText.membersDiffer(changed.map(\.shownEmail))) }
            if !Set(review.missing.map(\.userId)).isSubset(of: confirmed) { return .confirm(info.name, review.missing) }
        }
        guard review.version == UInt64(seq + 1) else { throw moved }
        guard activeId == id, sessions[id] === session else { return .skipped }
        let next = UInt64(epoch + 1)
        // This account's own wrap epoch-bound (v2) when every app of the account reads it.
        let bound = session.accountWrapsV2
        let account = session.account
        let name = info.name
        let digest = review.digest
        let made: (keys: [JSON], items: [JSON], meta: String, roster: String, epochPin: String)
        do {
            made = try await core {
                let nv = bound ? try account.newVaultKeyBound(vaultId: vid, keyEpoch: next) : try account.newVaultKey(vaultId: vid)
                let epochPin = try nv.key.epochPinJson(vaultId: vid, keyEpoch: next)
                var keys: [JSON] = []
                for m in members {
                    if m.userId == me {
                        keys.append(["user_id": .string(me), "wrapped_key": .string(nv.wrapped), "key_kind": .string(VaultInfo.accountKeyKind)])
                    } else {
                        let share = try signing.sealAndSignShare(vaultKey: nv.key, vaultId: vid, recipientJson: m.identity, role: m.role, keyEpoch: next)
                        keys.append(["user_id": .string(m.userId), "wrapped_key": .string(share.sealedKey), "key_kind": "sealed",
                                     "signature": .string(share.signature)])
                    }
                }
                let (items, meta) = try Self.reencrypt(rows, vid: vid, name: name, oldKey: oldKey, newKey: nv.key)
                let roster = try signing.signRoster(vaultKey: nv.key, vaultId: vid, previous: trusted, keyEpoch: next, membersJson: membersJson,
                                                    reviewed: digest)
                return (keys, items, meta, roster, epochPin)
            }
        } catch let e as CoreError {
            if case .ReviewMismatch = e { throw moved }
            throw e
        }
        let body: [String: JSON] = ["keys": .array(made.keys), "items": .array(made.items), "meta": .string(made.meta),
                                    "key_epoch": .int(epoch), "roster": .string(made.roster)]
        // The pinned email first (the server's listing only for people not pinned).
        let emailOf: (String) -> String = { uid in
            KeyPinsReader.email(pins, uid)
                ?? members.first { $0.userId == uid }.flatMap { $0.email.isEmpty ? nil : SharingText.shownEmail($0.email) }
                ?? SharingText.unknownMember
        }
        do {
            try await postRotation(id, vid, body)
        } catch let e as ApiError where e.status == 409 && e.hasCode("members_changed") {
            let f = e.fields
            let ids = ["unknown", "identity_changed", "role_changed", "missing"].flatMap { f?[$0]?.array.compactMap(\.string) ?? [] }
            throw MembersChanged(text: ids.isEmpty ? apiErrorText(e) : SharingText.membersDiffer(ids.map(emailOf)))
        } catch let e as ApiError where e.status == 409 && e.hasCode("member_roster_changed") {
            throw MembersChanged(text: apiErrorText(e))
        }
        // The key this device gave the vault, with the roster it signed (round 5).
        await recordOwnRotation(id, session, vaultId: vid, epochPin: made.epochPin, roster: made.roster)
        // The roster this device signed is the one it trusts now; members seen for the first time
        // in a version-1 review are pinned, unverified, with the emails the review showed.
        var remembered = loadMemory(id, session)
        remembered.rosters[vid] = made.roster
        if !onlyMe, !remembered.signed.contains(vid) { remembered.signed.append(vid) }
        saveMemory(id, session, remembered)
        // After a version-1 review: with the emails the review showed (kept with its digest), not
        // this second members answer's.
        let shownEmails = review.first ? reviewedEmails[vid]?[review.digest] : nil
        reviewedEmails[vid] = nil
        // A later review shows no one to compare (round 5 Info): people new to the pins stay
        // unpinned (each is checked, and compared, where they are first shown) instead of being
        // pinned with an email the user never saw.
        let toPin = review.first ? review.members.filter { !$0.isSelf && ($0.pin == "new" || $0.pin == "upgraded") } : []
        if !toPin.isEmpty {
            let now = Int64(Date().timeIntervalSince1970)
            try? await updatePins(id, session) { pins in
                var p = pins
                for person in toPin {
                    guard let m = members.first(where: { $0.userId == person.userId }) else { continue }
                    guard let email = shownEmails?[m.userId] else { continue }
                    p = try pinSet(pinsJson: p, identityJson: m.identity, email: email, verified: false, now: now)
                }
                return p
            }
        }
        try await syncLocked()
        return .rotated
    }
}
