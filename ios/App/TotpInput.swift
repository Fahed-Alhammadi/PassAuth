import AVFoundation
import PassAuthKit
import PhotosUI
import SwiftUI

/// The item editor's authenticator key: type it, scan its QR code (camera or an image from
/// Photos) or paste it. The label sits above the box: no placeholder inside it.
struct TotpField: View {
    @Environment(AppModel.self) private var model
    @Binding var value: String
    @Environment(\.dynamicTypeSize) private var typeSize
    @State private var scanning = false
    @State private var denied = false
    @State private var photo: PhotosPickerItem?

    var body: some View {
        LabeledInput(label: "Authenticator key (TOTP)", text: $value, mono: true, autocap: .never, identifier: "edit.totp")
        if !value.trimmingCharacters(in: .whitespaces).isEmpty, let problem = OtpAuth.parse(value).problem {
            Text(problem).font(.footnote).foregroundStyle(Color.paDanger)
        }
        VStack(alignment: .leading, spacing: 10) {
            Text("Scan the QR code from the website's two-step login setup, or paste its key or otpauth:// link.")
                .font(.footnote).foregroundStyle(Color.paMuted)
            // Wraps onto more lines when the buttons don't fit; one per line at accessibility sizes.
            if typeSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: 8) { buttons }
            } else {
                FlowRow(spacing: 8) { buttons }
            }
        }
        .padding(.vertical, 2)
        .fullScreenCover(isPresented: $scanning) {
            QrScanSheet { key in accept(key) }
        }
        .alert("Camera access is off", isPresented: $denied) {
            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
            }
            Button("Type the key", role: .cancel) {}
        } message: {
            Text("PassAuth uses the camera only to read the QR code and never keeps pictures. Allow camera access in Settings, or type or paste the key instead: on the website, look for \"Can't scan?\" or \"Enter a setup key\".")
        }
        .onChange(of: photo) { _, item in
            guard let item else { return }
            photo = nil
            Task { await readImage(item) }
        }
    }

    @ViewBuilder
    private var buttons: some View {
        Button(action: scan) { ButtonLabel(title: "Scan QR code", symbol: "qrcode.viewfinder") }
            .buttonStyle(.bordered)
            .accessibilityIdentifier("totp.scan")
        PhotosPicker(selection: $photo, matching: .images) { ButtonLabel(title: "Choose image", symbol: "photo") }
            .buttonStyle(.bordered)
            .accessibilityHint("Reads a QR code from a picture or screenshot")
            .accessibilityIdentifier("totp.image")
        PasteButton(payloadType: String.self) { strings in
            let text = strings.first ?? ""
            Task { @MainActor in acceptText(text, empty: "The clipboard is empty.") }
        }
        .labelStyle(.titleAndIcon)
        .buttonBorderShape(.capsule)
    }

    private func scan() {
        guard AVCaptureDevice.default(for: .video) != nil else {
            model.notify("No camera found. Type or paste the key, or choose an image of the QR code.")
            return
        }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            scanning = true
        case .notDetermined:
            Task {
                if await AVCaptureDevice.requestAccess(for: .video) { scanning = true } else { denied = true }
            }
        default:
            denied = true
        }
    }

    /// The image is decoded in memory and dropped; it isn't stored anywhere.
    private func readImage(_ item: PhotosPickerItem) async {
        guard let data = try? await item.loadTransferable(type: Data.self) else {
            model.notify("PassAuth couldn't open that image.")
            return
        }
        let codes = await Task.detached(priority: .userInitiated) { QrDecoder.decode(data: data) }.value
        guard !codes.isEmpty else {
            model.notify("No QR code found in that image.")
            return
        }
        // Prefer a code that holds a usable key.
        let text = codes.first { OtpAuth.parse($0).key != nil } ?? codes[0]
        acceptText(text, empty: "No QR code found in that image.")
    }

    private func acceptText(_ text: String, empty: String) {
        switch OtpAuth.parse(text) {
        case .valid(let key): accept(key)
        case .invalid(let reason): model.notify(text.trimmingCharacters(in: .whitespaces).isEmpty ? empty : reason)
        }
    }

    private func accept(_ key: OtpKey) {
        value = key.value
        model.notify(key.label.isEmpty ? "Authenticator key added." : "Authenticator key added for \(key.label).")
    }
}

/// Icon and title of a bordered button; the title wraps as a whole (large text).
private struct ButtonLabel: View {
    let title: String
    let symbol: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: symbol).accessibilityHidden(true)
            Text(title).multilineTextAlignment(.leading).fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Full-screen camera preview that reads an authenticator QR code. The capture output decodes
/// QR codes itself (`AVCaptureMetadataOutput`): PassAuth never sees, keeps or sends the frames.
private struct QrScanSheet: View {
    @Environment(\.dismiss) private var dismiss
    let onKey: (OtpKey) -> Void
    @State private var problem: String?
    @State private var cameraError: String?
    @State private var done = false

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            QrCameraView(onCode: handle, onError: { cameraError = $0 })
                .ignoresSafeArea()
                .accessibilityHidden(true)
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .stroke(.white.opacity(0.9), lineWidth: 3)
                .frame(width: 250, height: 250)
                .accessibilityHidden(true)
            VStack {
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }
                        .font(.body.weight(.semibold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 16).padding(.vertical, 8)
                        .background(.black.opacity(0.55), in: Capsule())
                }
                Spacer()
                Text(cameraError ?? problem ?? "Point the camera at the QR code from the website's two-step login setup.")
                    .font(.subheadline)
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)
                    .padding(14)
                    .background(.black.opacity(0.6), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .accessibilityAddTraits(.updatesFrequently)
            }
            .padding(20)
        }
        .statusBarHidden()
    }

    private func handle(_ text: String) {
        guard !done else { return }
        switch OtpAuth.parse(text) {
        case .valid(let key):
            done = true
            onKey(key)
            dismiss()
        case .invalid(let reason):
            if problem != reason {
                problem = reason
                UIAccessibility.post(notification: .announcement, argument: reason)
            }
        }
    }
}

/// The capture session lives on its own queue (start/stop block).
private final class CaptureBox: @unchecked Sendable {
    let session = AVCaptureSession()
    let queue = DispatchQueue(label: "io.passauth.qr-capture")
}

private struct QrCameraView: UIViewControllerRepresentable {
    let onCode: (String) -> Void
    let onError: (String) -> Void

    func makeUIViewController(context: Context) -> QrCameraController {
        let c = QrCameraController()
        c.onCode = onCode
        c.onError = onError
        return c
    }

    func updateUIViewController(_ c: QrCameraController, context: Context) {
        c.onCode = onCode
        c.onError = onError
    }
}

private final class QrCameraController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    var onError: ((String) -> Void)?
    private let box = CaptureBox()
    private var preview: AVCaptureVideoPreviewLayer?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        let session = box.session
        guard let device = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input) else {
            onError?("The camera couldn't be started. Type or paste the key instead.")
            return
        }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else {
            onError?("The camera couldn't be started. Type or paste the key instead.")
            return
        }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = output.availableMetadataObjectTypes.contains(.qr) ? [.qr] : []
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(layer)
        preview = layer
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        let box = box
        box.queue.async { if !box.session.isRunning && !box.session.inputs.isEmpty { box.session.startRunning() } }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        let box = box
        box.queue.async { if box.session.isRunning { box.session.stopRunning() } }
    }

    nonisolated func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        let texts = metadataObjects.compactMap { ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue }
        guard let text = texts.first else { return }
        MainActor.assumeIsolated { onCode?(text) }
    }
}

/// Lays its children out left to right, wrapping onto new lines (each child at its ideal size,
/// never wider than the row).
struct FlowRow: Layout {
    var spacing: CGFloat = 8

    private func rows(_ width: CGFloat, _ subviews: Subviews) -> [[(Int, CGSize)]] {
        var rows: [[(Int, CGSize)]] = [[]]
        var x: CGFloat = 0
        for (i, v) in subviews.enumerated() {
            var size = v.sizeThatFits(.unspecified)
            if size.width > width { size = v.sizeThatFits(ProposedViewSize(width: width, height: nil)) }
            if x > 0 && x + size.width > width {
                rows.append([])
                x = 0
            }
            rows[rows.count - 1].append((i, size))
            x += size.width + spacing
        }
        return rows
    }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let r = rows(proposal.width ?? .infinity, subviews)
        var height: CGFloat = 0
        var used: CGFloat = 0
        for row in r {
            var w: CGFloat = 0
            var h: CGFloat = 0
            for (_, size) in row {
                w += size.width
                h = max(h, size.height)
            }
            w += spacing * CGFloat(max(row.count - 1, 0))
            used = max(used, w)
            height += h
        }
        height += spacing * CGFloat(max(r.count - 1, 0))
        return CGSize(width: proposal.width ?? used, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in rows(bounds.width, subviews) {
            var h: CGFloat = 0
            for (_, size) in row { h = max(h, size.height) }
            var x = bounds.minX
            for (i, size) in row {
                subviews[i].place(at: CGPoint(x: x, y: y + (h - size.height) / 2), proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += h + spacing
        }
    }
}
