import PassAuthKit

extension VaultRepository {
    /// For the tests of client rules that script a server from before signed sharing (their
    /// `/api/config` lists other features, or nothing): release builds, and every test that
    /// doesn't ask for this, refuse such a server (`ServerSupport`, `ServerSupportTests`).
    @MainActor
    func allowingOlderServers() -> VaultRepository {
        requiresSignedSharing = false
        return self
    }
}
