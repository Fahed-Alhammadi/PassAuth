import AuthenticationServices
import PassAuthKit
import SwiftUI
import UIKit

/// PassAuth's AutoFill credential provider: passwords, passkeys, (iOS 18) verification codes,
/// and (iOS 26.2) saving logins and generating passwords for Safari and apps. iOS calls one of
/// the `prepare…` methods before showing the view, or a `…WithoutUserInteraction…` method
/// (QuickType suggestion, save, generate) that may ask for the view with `userInteractionRequired`.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var model: AutofillModel?
    private var host: UIHostingController<AutofillRoot>?

    private func show(_ request: AutofillRequest) {
        let m = AutofillModel(request: request)
        m.context = extensionContext
        model = m
        host?.willMove(toParent: nil)
        host?.view.removeFromSuperview()
        host?.removeFromParent()
        let h = UIHostingController(rootView: AutofillRoot(model: m))
        addChild(h)
        h.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(h.view)
        NSLayoutConstraint.activate([
            h.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            h.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            h.view.topAnchor.constraint(equalTo: view.topAnchor),
            h.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        h.didMove(toParent: self)
        host = h
        Task { await m.start(); applyTheme(m.state.settings.theme) }
    }

    private func applyTheme(_ t: ThemeMode) {
        overrideUserInterfaceStyle = t == .light ? .light : t == .dark ? .dark : .unspecified
    }

    // MARK: Lists

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.list(pages: AutofillMatcher.pages(serviceIdentifiers), passkey: nil))
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {
        show(.list(pages: AutofillMatcher.pages(serviceIdentifiers), passkey: PasskeyQuery(requestParameters)))
    }

    @available(iOS 18.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.oneTimeCodes(pages: AutofillMatcher.pages(serviceIdentifiers)))
    }

    // MARK: Suggestions (QuickType bar, passkey sheet)

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

    // MARK: Saving logins (iOS 26.2, capability SupportsSavePasswordCredentials)

    @available(iOS 26.2, *)
    override func performWithoutUserInteractionIfPossible(savePasswordRequest: ASSavePasswordRequest) {
        let ctx = extensionContext
        let info = SaveInfo(savePasswordRequest)
        Task { await AutofillModel.saveWithoutUserInteraction(info, context: ctx) }
    }

    @available(iOS 26.2, *)
    override func prepareInterface(for savePasswordRequest: ASSavePasswordRequest) {
        show(.save(SaveInfo(savePasswordRequest)))
    }

    // MARK: Generating passwords (iOS 26.2, capability SupportsGeneratePasswordCredentials)

    @available(iOS 26.2, *)
    override func performWithoutUserInteraction(generatePasswordsRequest: ASGeneratePasswordsRequest) {
        AutofillModel.generateWithoutUserInteraction(GenerateInfo(generatePasswordsRequest), context: extensionContext)
    }

    @available(iOS 26.2, *)
    override func prepareInterface(for generatePasswordsRequest: ASGeneratePasswordsRequest) {
        show(.generate(GenerateInfo(generatePasswordsRequest)))
    }

    // MARK: Configuration

    override func prepareInterfaceForExtensionConfiguration() {
        show(.configuration)
    }
}
