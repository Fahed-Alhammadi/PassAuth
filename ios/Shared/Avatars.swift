import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

/// Profile pictures (server feature `avatar`): the account's picture is a small square JPEG,
/// sealed with the Account Key by the core (`sealAvatar` / `openAvatar`) and stored by the server
/// under `/account/avatar`. `/sync` `user.avatar_seq` says which version the server has.
public enum AvatarImage {
    /// The server feature that announces profile pictures.
    public static let feature = "avatar"
    /// Edge of the square picture, in pixels.
    public static let edge = 256
    /// The core's limit (`MAX_AVATAR_BYTES`).
    public static let maxBytes = 256 * 1024

    /// The picture to upload from a chosen image file: rotated upright, centre-cropped to a
    /// square, resized to 256×256 and re-encoded as JPEG (quality 0.85, lowered until it fits
    /// 256 KiB). Re-encoding drops EXIF/GPS: the original file is never sent. Nil when the data
    /// isn't an image.
    public static func prepare(_ data: Data) -> Data? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              CGImageSourceGetCount(source) > 0,
              let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
              let w = (props[kCGImagePropertyPixelWidth] as? NSNumber)?.doubleValue,
              let h = (props[kCGImagePropertyPixelHeight] as? NSNumber)?.doubleValue,
              w >= 1, h >= 1 else { return nil }
        // Decode only as large as needed: the short side at least `edge` (capped for huge panoramas).
        let long = max(w, h), short = min(w, h)
        let maxPixel = min(max(Double(edge), (Double(edge) * long / short).rounded(.up)), 8192)
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
            kCGImageSourceThumbnailMaxPixelSize: maxPixel,
        ]
        guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary) else { return nil }
        return render(image)
    }

    /// `image` centre-cropped, scaled to `edge`×`edge` and encoded as JPEG ≤ `maxBytes`.
    static func render(_ image: CGImage) -> Data? {
        let iw = CGFloat(image.width), ih = CGFloat(image.height)
        guard iw >= 1, ih >= 1, let space = CGColorSpace(name: CGColorSpace.sRGB),
              let ctx = CGContext(data: nil, width: edge, height: edge, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                                  bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) else { return nil }
        // A transparent picture gets a white background (JPEG has no alpha).
        ctx.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        ctx.fill(CGRect(x: 0, y: 0, width: edge, height: edge))
        ctx.interpolationQuality = .high
        let scale = CGFloat(edge) / min(iw, ih)
        let dw = iw * scale, dh = ih * scale
        ctx.draw(image, in: CGRect(x: (CGFloat(edge) - dw) / 2, y: (CGFloat(edge) - dh) / 2, width: dw, height: dh))
        guard let square = ctx.makeImage() else { return nil }
        var quality = 0.85
        while quality > 0.05 {
            if let jpeg = jpeg(square, quality: quality), jpeg.count <= maxBytes { return jpeg }
            quality -= 0.15
        }
        return nil
    }

    static func jpeg(_ image: CGImage, quality: Double) -> Data? {
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(dest, image, [kCGImageDestinationLossyCompressionQuality: quality] as CFDictionary)
        guard CGImageDestinationFinalize(dest) else { return nil }
        return out as Data
    }
}

/// What a sync means for the cached picture of an account.
public enum AvatarSyncAction: Equatable, Sendable {
    case none
    /// Ask the server for the picture (`GET /account/avatar`).
    case fetch
    /// The account has no picture any more: drop the cached one.
    case clear

    /// `serverSeq` = `/sync` `user.avatar_seq` (nil from servers without pictures), `cachedSeq` =
    /// the version this device last fetched (nil = none), `hasFile` = a cached picture is there.
    /// A version fetched once isn't asked again, even when it didn't open (initials).
    public static func decide(serverSeq: Int64?, cachedSeq: Int64?, hasFile: Bool) -> AvatarSyncAction {
        guard let serverSeq else { return .none }
        if serverSeq <= 0 { return (cachedSeq ?? 0) != 0 || hasFile ? .clear : .none }
        return serverSeq != cachedSeq ? .fetch : .none
    }
}

/// The cached pictures of the accounts on this device: `<account id>.jpg` in the app's own
/// container (not the App Group: the AutoFill extension doesn't show pictures), readable after
/// the first unlock (the sign-in screen and account switcher show them), excluded from backup.
public final class AvatarCache: Sendable {
    public let directory: URL

    public init(directory: URL? = nil) {
        self.directory = directory ?? Self.defaultDirectory()
    }

    static func defaultDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("avatars", isDirectory: true)
    }

    func url(_ id: String) -> URL {
        directory.appendingPathComponent("\(id.filter { $0.isLetter || $0.isNumber || $0 == "-" }).jpg")
    }

    public func read(_ id: String) -> Data? { try? Data(contentsOf: url(id)) }

    public func has(_ id: String) -> Bool { FileManager.default.fileExists(atPath: url(id).path) }

    public func write(_ id: String, _ jpeg: Data) {
        let fm = FileManager.default
        #if os(iOS)
        let attrs: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
        let options: Data.WritingOptions = [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
        #else
        let attrs: [FileAttributeKey: Any] = [:]
        let options: Data.WritingOptions = [.atomic]
        #endif
        try? fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: attrs)
        var u = url(id)
        guard (try? jpeg.write(to: u, options: options)) != nil else { return }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? u.setResourceValues(values)
    }

    public func delete(_ id: String) { try? FileManager.default.removeItem(at: url(id)) }

    /// Every cached picture, by account id.
    public func all() -> [String: Data] {
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        var out: [String: Data] = [:]
        for f in files where f.pathExtension == "jpg" {
            if let d = try? Data(contentsOf: f) { out[f.deletingPathExtension().lastPathComponent] = d }
        }
        return out
    }
}
