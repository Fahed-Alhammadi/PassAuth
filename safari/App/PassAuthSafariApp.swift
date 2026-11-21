import SwiftUI

/// "PassAuth for Safari": a small app that carries the PassAuth Safari extension (iPhone, iPad, Mac).
/// Its only screen says how to turn the extension on; everything else happens in Safari.
@main
struct PassAuthSafariApp: App {
    var body: some Scene {
        WindowGroup {
            SetupView()
            #if os(macOS)
                .frame(minWidth: 460, minHeight: 560)
            #endif
        }
        #if os(macOS)
        .windowResizability(.contentSize)
        #endif
    }
}
