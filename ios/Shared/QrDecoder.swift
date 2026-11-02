import CoreImage
import Foundation

/// Finds QR codes in an image chosen by the user (Photos), in memory only. Camera scanning
/// doesn't come here: `AVCaptureMetadataOutput` decodes the frames itself.
public enum QrDecoder {
    /// The texts of the QR codes in the image, or [] if there are none. Also tries the inverted
    /// image (light-on-dark codes of dark mode setup pages).
    public static func decode(_ image: CIImage) -> [String] {
        let context = CIContext(options: [.cacheIntermediates: false])
        guard let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: context, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]) else { return [] }
        let read = { (img: CIImage) in
            detector.features(in: img).compactMap { ($0 as? CIQRCodeFeature)?.messageString }.filter { !$0.isEmpty }
        }
        let found = read(image)
        if !found.isEmpty { return found }
        guard let inverted = CIFilter(name: "CIColorInvert", parameters: [kCIInputImageKey: image])?.outputImage else { return [] }
        return read(inverted)
    }

    /// Image file data (PNG, JPEG, HEIC …).
    public static func decode(data: Data) -> [String] {
        guard let image = CIImage(data: data, options: [.applyOrientationProperty: true]) else { return [] }
        return decode(image)
    }
}
