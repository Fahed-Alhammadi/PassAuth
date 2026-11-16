import PassAuthKit
import XCTest

/// API v2: the AutoFill extension names itself to the server on every request
/// (`X-PassAuth-Client: macos-autofill/<version>`; the iOS app's own test checks the requests).
final class ClientHeaderTests: XCTestCase {
    func testClientHeader() {
        XCTAssertEqual(ApiClient.clientHeaderName, "X-PassAuth-Client")
        XCTAssertTrue(ApiClient.clientHeader.hasPrefix("macos-autofill/"), ApiClient.clientHeader)
    }
}
