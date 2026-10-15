import Darwin

/// This is a local inode binding, not content authentication. The SQLite
/// certificate separately proves its open handle has not moved; the journal
/// continues to authenticate each normal refresh after reuse.
struct EventReaderFileIdentity: Equatable {
    let device: dev_t
    let inode: ino_t

    static func read(directory: String) -> Self? {
        var info = stat()
        guard lstat(directory + "/events.db", &info) == 0,
              info.st_mode & S_IFMT == S_IFREG else { return nil }
        return .init(device: info.st_dev, inode: info.st_ino)
    }
}
