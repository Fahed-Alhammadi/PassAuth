import PassAuthKit
import SwiftUI
import UIKit

/// Site icon from the server, or the item's first letter when it can't be had. With website
/// icons turned off (the user's setting or the server's) every login shows the same globe.
struct SiteIcon: View {
    @Environment(AppModel.self) private var model
    let host: String
    let name: String
    var kind: ItemKind = .login
    var size: CGFloat = 36
    @State private var image: UIImage?

    var body: some View {
        let s = model.repo.state
        // The user's setting and the server's icon service (`SiteIcons.shown`).
        let iconsOn = s.showSiteIcons
        let enabled = iconsOn && !host.isEmpty
        RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
            // Site icons are drawn for light backgrounds: keep their tile light in dark mode too.
            .fill(enabled && image != nil ? Color.paIconTile : Color.paSurface2)
            .frame(width: size, height: size)
            .overlay {
                if enabled, let image {
                    Image(uiImage: image).resizable().interpolation(.high).scaledToFit().frame(width: size * 0.6, height: size * 0.6)
                } else if SiteIconGlyph.symbol(iconsOn: iconsOn, kind: kind) != nil {
                    SiteIconGlyph.globe(size: size)
                } else if kind == .login {
                    Text(String(name.trimmingCharacters(in: .whitespaces).first ?? "?").uppercased())
                        .font(.system(size: size * 0.42, weight: .semibold))
                        .foregroundStyle(Color.paAccent)
                } else {
                    Image(systemName: kind.symbol).font(.system(size: size * 0.42)).foregroundStyle(Color.paAccent)
                }
            }
            .task(id: "\(s.server)|\(host)|\(enabled)") {
                image = enabled ? await model.icons.load(server: s.server, host: host) : nil
            }
            .accessibilityHidden(true)
    }
}


/// The glyph every login shows while website icons are off.
enum SiteIconGlyph {
    static let symbol = "globe"

    /// Which glyph a login tile shows: the globe with icons off, else its letter (nil).
    static func symbol(iconsOn: Bool, kind: ItemKind) -> String? {
        kind == .login && !iconsOn ? symbol : nil
    }

    @MainActor static func globe(size: CGFloat) -> some View {
        Image(systemName: symbol).font(.system(size: size * 0.42, weight: .medium)).foregroundStyle(Color.paMuted)
    }
}
