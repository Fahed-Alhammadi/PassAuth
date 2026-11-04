import CoreTransferable
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// The Emergency Kit (what a user needs to sign in on a new device), as the web vault's
/// `kit.ts`: server, email, Secret Key and a blank line to write the master password on.
enum EmergencyKit {
    static let intro = "Print this page or keep it somewhere safe and offline, such as a drawer or a safe. You need it to sign in on a new device. Nobody, not even your server administrator, can recover your master password or Secret Key for you."
    static let warning = "Write your master password by hand only if this kit is stored somewhere nobody else can reach."

    static func text(server: String, email: String, secretKey: String) -> String {
        [
            "PassAuth Emergency Kit", "",
            "Server:      \(server)",
            "Email:       \(email)",
            "Secret Key:  \(secretKey)", "",
            "Master password: ______________________________", "",
            "Keep this kit somewhere safe and offline, such as a printed copy in a drawer",
            "or safe. You need the Secret Key and your master password to sign in on a new",
            "device. PassAuth cannot recover either of them for you.", "",
        ].joined(separator: "\n")
    }

    /// A one-page PDF (US Letter) of the kit, made in memory.
    @MainActor
    static func pdf(server: String, email: String, secretKey: String) -> Data {
        let page = CGRect(x: 0, y: 0, width: 612, height: 792)
        let meta = UIGraphicsPDFRendererFormat()
        meta.documentInfo = [kCGPDFContextTitle as String: "PassAuth Emergency Kit", kCGPDFContextCreator as String: "PassAuth"]
        let ink = UIColor(hex: 0x0B1A3A), muted = UIColor(hex: 0x5A6A85), line = UIColor(hex: 0x8494AD)
        return UIGraphicsPDFRenderer(bounds: page, format: meta).pdfData { ctx in
            ctx.beginPage()
            let left: CGFloat = 56, width = page.width - 112
            var y: CGFloat = 60
            func draw(_ s: String, _ font: UIFont, _ color: UIColor = ink, gap: CGFloat = 8) {
                let p = NSMutableParagraphStyle()
                p.lineBreakMode = .byWordWrapping
                let a = NSAttributedString(string: s, attributes: [.font: font, .foregroundColor: color, .paragraphStyle: p])
                let h = ceil(a.boundingRect(with: CGSize(width: width, height: .greatestFiniteMagnitude), options: [.usesLineFragmentOrigin], context: nil).height)
                a.draw(with: CGRect(x: left, y: y, width: width, height: h), options: [.usesLineFragmentOrigin], context: nil)
                y += h + gap
            }
            draw("PassAuth Emergency Kit", .systemFont(ofSize: 26, weight: .bold))
            draw("Created \(Date().formatted(date: .long, time: .omitted))", .systemFont(ofSize: 12), muted, gap: 18)
            draw(intro, .systemFont(ofSize: 13), gap: 22)
            let rows: [(String, String, Bool)] = [("SERVER", server, true), ("EMAIL", email, false), ("SECRET KEY", secretKey, true), ("MASTER PASSWORD", "", false)]
            for (label, value, mono) in rows {
                draw(label, .systemFont(ofSize: 10, weight: .semibold), muted, gap: 4)
                if value.isEmpty {
                    y += 30
                    let path = UIBezierPath()
                    path.move(to: CGPoint(x: left, y: y))
                    path.addLine(to: CGPoint(x: left + width, y: y))
                    ink.setStroke()
                    path.lineWidth = 1
                    path.stroke()
                    y += 20
                } else {
                    draw(value, mono ? .monospacedSystemFont(ofSize: 15, weight: .medium) : .systemFont(ofSize: 15), gap: 10)
                    let path = UIBezierPath()
                    path.move(to: CGPoint(x: left, y: y))
                    path.addLine(to: CGPoint(x: left + width, y: y))
                    line.setStroke()
                    path.lineWidth = 0.5
                    path.stroke()
                    y += 14
                }
            }
            y += 6
            draw(warning, .systemFont(ofSize: 12, weight: .medium), UIColor(hex: 0x6B4000))
        }
    }
}

/// The kit as a PDF for the share sheet (Save to Files, Print, AirDrop…). The data is made
/// when the screen opens and dropped with it.
struct EmergencyKitPDF: Transferable {
    let data: Data

    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .pdf) { $0.data }
            .suggestedFileName("PassAuth Emergency Kit.pdf")
    }
}
