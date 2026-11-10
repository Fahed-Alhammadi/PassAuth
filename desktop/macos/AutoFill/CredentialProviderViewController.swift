import AppKit
import AuthenticationServices
import PassAuthKit
import SwiftUI
import os

/// Counts only: `log show --predicate 'subsystem == "io.passauth.autofill"'`.
private let log = Logger(subsystem: "io.passauth.autofill", category: "requests")

/// PassAuth's AutoFill credential provider for macOS (embedded in the desktop app): passwords,
/// passkeys and (macOS 15) verification codes for Safari and apps. Same flow as the iOS
/// extension (`ios/AutoFill`, whose `AutofillModel` this target compiles), plus its own
/// sign-in: it doesn't share anything with the desktop app.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var model: AutofillModel?
    private var host: NSHostingView<MacAutofillRoot>?

    override func loadView() {
        view = NSView(frame: NSRect(origin: .zero, size: Self.size))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        preferredContentSize = Self.size
    }

    static let size = NSSize(width: 460, height: 560)

    private func show(_ request: AutofillRequest) {
        let m = AutofillModel(request: request)
        m.context = extensionContext
        model = m
        host?.removeFromSuperview()
        let h = NSHostingView(rootView: MacAutofillRoot(model: m))
        h.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(h)
        NSLayoutConstraint.activate([
            h.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            h.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            h.topAnchor.constraint(equalTo: view.topAnchor),
            h.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        host = h
        Task { await m.start(); applyTheme(m.state.settings.theme) }
    }

    private func applyTheme(_ t: ThemeMode) {
        view.appearance = t == .light ? NSAppearance(named: .aqua) : t == .dark ? NSAppearance(named: .darkAqua) : nil
    }

    // MARK: Lists

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let pages = AutofillMatcher.pages(serviceIdentifiers)
        log.notice("list request: \(serviceIdentifiers.count) service identifiers (\(serviceIdentifiers.filter { $0.type == .URL }.count) URL, \(serviceIdentifiers.filter { $0.type == .domain }.count) domain) → \(pages.count) pages")
        show(.list(pages: pages, passkey: nil))
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {
        show(.list(pages: AutofillMatcher.pages(serviceIdentifiers), passkey: PasskeyQuery(requestParameters)))
    }

    @available(macOS 15.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.oneTimeCodes(pages: AutofillMatcher.pages(serviceIdentifiers)))
    }

    // MARK: Suggestions

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        let ctx = extensionContext
        Task { await AutofillModel.provideWithoutUserInteraction(credentialRequest, context: ctx) }
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        show(.credential(credentialRequest))
    }

    // MARK: Passkey registration

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let r = registrationRequest as? ASPasskeyCredentialRequest else {
            extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue))
            return
        }
        show(.registerPasskey(r))
    }

    // MARK: Configuration (PassAuth turned on in System Settings, or its Options button)

    override func prepareInterfaceForExtensionConfiguration() {
        // Expired kept keys go as soon as the configuration screen opens.
        let store = SecureStore(role: .app)
        store.load()
        TimedUnlock.purgeExpired(VaultRepository(store: store, api: ApiClient(store: store)))
        show(.configuration)
    }
}
