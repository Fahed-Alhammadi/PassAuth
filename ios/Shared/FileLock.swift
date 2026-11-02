import Foundation

/// An exclusive advisory lock (`flock`) on a file in the App Group container, shared by the
/// app and its AutoFill extension (separate processes). The kernel drops it when the holder
/// exits, so a crashed process never leaves it stuck.
///
/// iOS terminates an app that is suspended while holding a lock on a file in a shared
/// container, so locks are only taken with a timeout, held briefly, and (in the app) inside a
/// background task.
public final class FileLock: @unchecked Sendable {
    private var fd: Int32

    private init(fd: Int32) { self.fd = fd }

    deinit { release() }

    /// The lock file `name` in PassAuth's data directory.
    public static func url(_ name: String, directory: URL? = nil) -> URL {
        (directory ?? SharedConfig.dataDirectory()).appendingPathComponent(".\(name).lock")
    }

    /// Take the lock if it is free right now.
    public static func tryAcquire(_ url: URL) -> FileLock? {
        let fd = open(url.path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return nil }
        if flock(fd, LOCK_EX | LOCK_NB) == 0 { return FileLock(fd: fd) }
        close(fd)
        return nil
    }

    /// Wait (blocking, briefly) for the lock; nil after `timeout` seconds.
    public static func acquireSync(_ url: URL, timeout: TimeInterval = 2) -> FileLock? {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if let l = tryAcquire(url) { return l }
            usleep(2_000)
        } while Date() < deadline
        return nil
    }

    /// Wait (suspending) for the lock; nil after `timeout` seconds.
    public static func acquire(_ url: URL, timeout: TimeInterval) async -> FileLock? {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if let l = tryAcquire(url) { return l }
            try? await Task.sleep(for: .milliseconds(25))
        } while Date() < deadline
        return nil
    }

    public func release() {
        guard fd >= 0 else { return }
        flock(fd, LOCK_UN)
        close(fd)
        fd = -1
    }
}
