import PassAuthKit
import SwiftUI
import UIKit

/// Site icon from the server, or the item's first letter.
struct SiteIcon: View {
    @Environment(AppModel.self) private var model
    let host: String
    let name: String
    var kind: ItemKind = .login
    var size: CGFloat = 36
    @State private var image: UIImage?

    var body: some View {
        let s = model.repo.state
        let enabled = s.settings.showIcons && !host.isEmpty
        RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
            // Site icons are drawn for light backgrounds: keep their tile light in dark mode too.
            .fill(enabled && image != nil ? Color.paIconTile : Color.paSurface2)
            .frame(width: size, height: size)
            .overlay {
                if enabled, let image {
                    Image(uiImage: image).resizable().interpolation(.high).scaledToFit().frame(width: size * 0.6, height: size * 0.6)
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

