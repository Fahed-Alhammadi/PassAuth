import Foundation
import PassAuthKit
import XCTest

/// The first-launch permissions screen: shown once, and how statuses are read.
final class PermissionsTests: XCTestCase {
    func testIntroShownOnceBeforeTheFirstAccount() {
        var m = PermissionMemory()
        XCTAssertTrue(PermissionRules.showIntro(m, hasAccounts: false))
        XCTAssertFalse(PermissionRules.showIntro(m, hasAccounts: false, skip: true))
        // Updated from a version without the screen: accounts exist already.
        XCTAssertFalse(PermissionRules.showIntro(m, hasAccounts: true))
        m.introShown = true
        XCTAssertFalse(PermissionRules.showIntro(m, hasAccounts: false))
    }

    func testMemoryIsSharedSettingsAndSurvivesOldFiles() throws {
        var s = Settings()
        s.permissions.introShown = true
        s.permissions.localNetwork = .denied
        s.permissions.biometricsAllowed = true
        let back = try JSONDecoder().decode(Settings.self, from: JSONEncoder().encode(s))
        XCTAssertEqual(back.permissions, s.permissions)
        // Settings written before the screen existed, and junk values, fall back to the defaults.
        let old = try JSONDecoder().decode(Settings.self, from: Data(#"{"theme":"dark"}"#.utf8))
        XCTAssertEqual(old.permissions, PermissionMemory())
        XCTAssertEqual(old.theme, .dark)
        let junk = try JSONDecoder().decode(Settings.self, from: Data(#"{"permissions":{"introShown":"yes","localNetwork":"maybe","biometricOffered":true}}"#.utf8))
        XCTAssertFalse(junk.permissions.introShown)
        XCTAssertNil(junk.permissions.localNetwork)
        XCTAssertTrue(junk.permissions.biometricOffered)
    }

    func testBiometricOfferOnce() {
        var m = PermissionMemory()
        XCTAssertFalse(PermissionRules.offerBiometricUnlock(m, available: true, enabled: false))
        m.biometricsAllowed = true
        XCTAssertTrue(PermissionRules.offerBiometricUnlock(m, available: true, enabled: false))
        XCTAssertFalse(PermissionRules.offerBiometricUnlock(m, available: false, enabled: false))
        XCTAssertFalse(PermissionRules.offerBiometricUnlock(m, available: true, enabled: true))
        m.biometricOffered = true
        XCTAssertFalse(PermissionRules.offerBiometricUnlock(m, available: true, enabled: false))
    }

    func testCamera() {
        XCTAssertEqual(PermissionRules.camera(0), .notAsked)
        XCTAssertEqual(PermissionRules.camera(1), .unavailable)
        XCTAssertEqual(PermissionRules.camera(2), .denied)
        XCTAssertEqual(PermissionRules.camera(3), .allowed)
        XCTAssertEqual(PermissionRules.camera(9), .unknown)
    }

    func testBiometrics() {
        let f = PermissionRules.biometrics
        XCTAssertEqual(f(true, nil, true, false), .notAsked)
        XCTAssertEqual(f(true, nil, true, true), .allowed)
        // Face ID turned off for PassAuth.
        XCTAssertEqual(f(false, -6, true, true), .denied)
        XCTAssertEqual(f(false, -6, true, false), .denied)
        // Not enrolled / no passcode / no hardware.
        XCTAssertEqual(f(false, -7, true, false), .unavailable)
        XCTAssertEqual(f(false, -5, true, false), .unavailable)
        XCTAssertEqual(f(false, -6, false, false), .unavailable)
        // Locked out after failed attempts: the permission is unchanged.
        XCTAssertEqual(f(false, -8, true, true), .allowed)
        XCTAssertEqual(f(false, -8, true, false), .notAsked)
    }

    func testAutofill() {
        XCTAssertEqual(PermissionRules.autofill(true), .allowed)
        XCTAssertEqual(PermissionRules.autofill(false), .notAsked)
        // The identity store didn't answer (iOS 27.0 simulator).
        XCTAssertEqual(PermissionRules.autofill(nil), .unknown)
    }

    func testLocalNetwork() {
        let f = PermissionRules.localNetwork
        XCTAssertEqual(PermissionRules.probeEvent(dnsError: -65570, failed: false), .policyDenied)
        XCTAssertEqual(PermissionRules.probeEvent(dnsError: -65570, failed: true), .policyDenied)
        XCTAssertEqual(PermissionRules.probeEvent(dnsError: -65537, failed: false), .waiting)
        XCTAssertEqual(PermissionRules.probeEvent(dnsError: nil, failed: true), .failed)
        XCTAssertEqual(f([.ready, .policyDenied], true), .denied)
        XCTAssertEqual(f([.policyDenied], false), .denied)
        XCTAssertEqual(f([.ready], true), .allowed)
        // Ready while the prompt may still be up proves nothing.
        XCTAssertEqual(f([.ready], false), .unknown)
        XCTAssertEqual(f([.ready, .failed], true), .unknown)
        XCTAssertEqual(f([], true), .unknown)
        var m = PermissionMemory()
        XCTAssertEqual(PermissionRules.localNetworkShown(m), .notAsked)
        m.localNetwork = .unknown
        XCTAssertEqual(PermissionRules.localNetworkShown(m), .unknown)
    }
}
