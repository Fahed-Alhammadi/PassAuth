import PassAuthCore
import UIKit
import XCTest

/// Profile picture on Settings → Account against a throwaway server (PA_SERVER): no picture
/// (initials, "Add profile picture"), a picture set from another device arriving by sync, then
/// Remove photo. PA_SHOTS gets the screenshots (`PA_SHOT_SUFFIX` is added to their names, e.g.
/// "-dark" for a run with the simulator in dark mode).
@MainActor
final class AvatarUITests: UITestBase {
    private var suffix: String { env["PA_SHOT_SUFFIX"] ?? "" }

    private func settingsPage(_ id: String) {
        tab("Settings")
        while !app.buttons["settings.\(id)"].exists && app.navigationBars.buttons.count > 0 && !app.navigationBars["Settings"].exists { back() }
        wait(app.buttons["settings.\(id)"]).tap()
    }

    private func waitLabel(_ e: XCUIElement, _ label: String, _ timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if e.exists && e.label == label { return true }
            usleep(300_000)
        }
        return false
    }

    /// A 256×256 JPEG standing in for a photo.
    private func picture() -> Data {
        let size = CGSize(width: 256, height: 256)
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        let image = UIGraphicsImageRenderer(size: size, format: format).image { ctx in
            let c = ctx.cgContext
            let colors = [UIColor(red: 0.98, green: 0.62, blue: 0.35, alpha: 1).cgColor, UIColor(red: 0.85, green: 0.25, blue: 0.45, alpha: 1).cgColor]
            let g = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors as CFArray, locations: [0, 1])!
            c.drawLinearGradient(g, start: .zero, end: CGPoint(x: 256, y: 256), options: [])
            UIColor(white: 1, alpha: 0.9).setFill()
            c.fillEllipse(in: CGRect(x: 88, y: 52, width: 80, height: 80))
            c.fillEllipse(in: CGRect(x: 48, y: 150, width: 160, height: 150))
        }
        return image.jpegData(compressionQuality: 0.85)!
    }

    func testProfilePicture() async throws {
        continueAfterFailure = false
        let email = "avatar-\(UUID().uuidString.prefix(8).lowercased())@example.com"
        app.launchArguments = ["-PAResetState"]
        app.launch()
        connect()
        register(email: email, name: "Alex Morgan", secretKey: false)

        settingsPage("account")
        let avatar = wait(app.buttons["account.avatar"])
        XCTAssertEqual(avatar.label, "Add profile picture")
        shot("avatar-account-none\(suffix)")

        // Set from "another device": the app gets it with the next sync.
        let helper = TestServer(server)
        let s = try await helper.login(email: email, password: password)
        let sealed = try s.account.sealAvatar(image: picture())
        try await helper.call("PUT", "/account/avatar", ["avatar": sealed], session: s)
        if !waitLabel(avatar, "Change profile picture", 15) {
            // No live sync: refresh from the vault list.
            tab("Vault")
            let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.3))
            start.press(forDuration: 0.05, thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.85)))
            sleep(2)
            settingsPage("account")
        }
        XCTAssertEqual(wait(app.buttons["account.avatar"]).label, "Change profile picture")
        sleep(1)
        shot("avatar-account-picture\(suffix)")
        back()
        shot("avatar-settings-picture\(suffix)")

        settingsPage("account")
        wait(app.buttons["account.avatar"]).tap()
        wait(button("Choose photo…"))
        shot("avatar-account-menu\(suffix)")
        confirm("Remove photo")
        XCTAssertTrue(waitLabel(app.buttons["account.avatar"], "Add profile picture", 15))
        let after = try await helper.call("GET", "/account/avatar", session: s)
        XCTAssertTrue(after["avatar"] is NSNull || after["avatar"] == nil)
    }
}
