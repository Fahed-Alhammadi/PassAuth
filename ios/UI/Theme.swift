import PassAuthCore
import PassAuthKit
import SwiftUI
import UIKit

// Neutral iOS-style surfaces (light: grouped gray on white cards; dark: true black with
// raised grays, no tinted backgrounds) with the PassAuth blue from assets/passauth-logo.svg as
// the only accent. Dark accents are lighter and less saturated. Text pairs meet WCAG AA
// (≥4.5:1) on their surfaces.
extension Color {
    private static func dyn(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(uiColor: UIColor { $0.userInterfaceStyle == .dark ? UIColor(hex: dark) : UIColor(hex: light) })
    }

    static let paAccent = dyn(0x0866ED, 0x3B8CFA)
    /// Fill behind white text (filled buttons): the brand blue in both modes, since white on the
    /// lighter dark-mode accent is only 3.3:1 (this is 4.9:1).
    static let paAccentFill = Color(uiColor: UIColor(hex: 0x0866ED))
    static let paAccentInk = dyn(0x0553C9, 0x8EC2FF)
    static let paAccentSoft = dyn(0xE7F0FE, 0x1C2633)
    static let paBackground = dyn(0xF2F2F7, 0x000000)
    static let paSurface = dyn(0xFFFFFF, 0x1C1C1E)
    static let paSurface2 = dyn(0xEDEDF2, 0x2C2C2E)
    static let paIconTile = dyn(0xF0F0F5, 0xE5E5EA)
    static let paInk = dyn(0x1C1C1E, 0xF2F2F7)
    static let paMuted = dyn(0x6C6C72, 0x9B9BA1)
    static let paLine = dyn(0xD8D8DE, 0x38383A)
    static let paOk = dyn(0x1F7A35, 0x4CD964)
    static let paWarn = dyn(0x965A00, 0xFFB340)
    static let paDanger = dyn(0xC4251B, 0xFF6B60)

    enum Brand {
        static let navy = Color(uiColor: UIColor(hex: 0x082052))
        static let blue = Color(uiColor: UIColor(hex: 0x0866ED))
        static let cyan = Color(uiColor: UIColor(hex: 0x23D5F4))
    }
}

extension UIColor {
    convenience init(hex: UInt32) {
        self.init(red: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255, blue: CGFloat(hex & 0xff) / 255, alpha: 1)
    }
}

// MARK: Screen chrome

extension View {
    /// Navigation bar in the page colour, following light and dark mode.
    func paNavBar() -> some View {
        toolbarBackground(Color.paBackground, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
    }

    /// Lists and forms on the brand background.
    func paList() -> some View {
        scrollContentBackground(.hidden).background(Color.paBackground)
    }

    func paRow() -> some View {
        listRowBackground(Color.paSurface)
    }
}

// MARK: Logo

/// The PassAuth shield, drawn from assets/passauth-logo.svg (viewBox 128×144).
struct LogoMark: View {
    var height: CGFloat = 56

    var body: some View {
        Canvas { ctx, size in
            let s = size.height / 144
            func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: x * s, y: y * s) }
            var shield = Path()
            shield.move(to: p(64, 5))
            shield.addLine(to: p(111, 27))
            shield.addQuadCurve(to: p(117, 39), control: p(117, 30))
            shield.addLine(to: p(117, 82))
            shield.addQuadCurve(to: p(64, 139), control: p(117, 114))
            shield.addQuadCurve(to: p(11, 82), control: p(11, 114))
            shield.addLine(to: p(11, 39))
            shield.addQuadCurve(to: p(17, 27), control: p(11, 30))
            shield.closeSubpath()
            // Gradient x1=0 y1=1 → x2=1 y2=0 over the shield's bounding box.
            let box = shield.boundingRect
            ctx.fill(shield, with: .linearGradient(
                Gradient(stops: [.init(color: Color.Brand.navy, location: 0), .init(color: Color.Brand.blue, location: 0.52), .init(color: Color.Brand.cyan, location: 1)]),
                startPoint: CGPoint(x: box.minX, y: box.maxY), endPoint: CGPoint(x: box.maxX, y: box.minY)))
            var letter = Path()
            letter.move(to: p(42, 30))
            letter.addLine(to: p(70, 30))
            letter.addCurve(to: p(103, 62), control1: p(95, 30), control2: p(103, 45))
            letter.addCurve(to: p(66, 96), control1: p(103, 82), control2: p(89, 96))
            letter.addLine(to: p(55, 96))
            letter.addLine(to: p(55, 121))
            letter.addLine(to: p(38, 112))
            letter.addLine(to: p(38, 30))
            letter.closeSubpath()
            letter.move(to: p(55, 48))
            letter.addLine(to: p(55, 78))
            letter.addLine(to: p(67, 78))
            letter.addCurve(to: p(84, 63), control1: p(79, 78), control2: p(84, 72))
            letter.addCurve(to: p(67, 48), control1: p(84, 54), control2: p(79, 48))
            letter.closeSubpath()
            ctx.fill(letter, with: .color(.white), style: FillStyle(eoFill: true))
            ctx.fill(Path(ellipseIn: CGRect(x: 64 * s, y: 54 * s, width: 10 * s, height: 10 * s)), with: .color(Color.Brand.navy))
            var hole = Path()
            hole.move(to: p(66.8, 62))
            hole.addLine(to: p(71.2, 62))
            hole.addLine(to: p(74, 71))
            hole.addLine(to: p(64, 71))
            hole.closeSubpath()
            ctx.fill(hole, with: .color(Color.Brand.navy))
        }
        .frame(width: height * 128 / 144, height: height)
        .accessibilityHidden(true)
    }
}

/// "PassAuth" with "Auth" in the brand blue.
struct Wordmark: View {
    var size: CGFloat = 24
    var body: some View {
        (Text("Pass").foregroundColor(Color.paInk) + Text("Auth").foregroundColor(Color.paAccent))
            .font(.system(size: size, weight: .bold))
            .accessibilityLabel("PassAuth")
    }
}

// MARK: Avatars and icons

/// Initials from the profile name ("Fahed Alhammadi" → "FA"), else from the email.
func initials(_ name: String, _ email: String) -> String {
    let words = name.split(whereSeparator: \.isWhitespace)
    if words.count > 1, let f = words.first?.first, let l = words.last?.first { return "\(f)\(l)".uppercased() }
    if words.count == 1 { return String(words[0].prefix(2)).uppercased() }
    let local = email.split(separator: "@").first.map(String.init) ?? ""
    let parts = local.split(whereSeparator: { "._-".contains($0) })
    let s: String
    if parts.count > 1, let a = parts[0].first, let b = parts[1].first { s = "\(a)\(b)" } else { s = String(parts.first?.prefix(2) ?? "") }
    return (s.isEmpty ? "?" : s).uppercased()
}

struct Avatar: View {
    let text: String
    var size: CGFloat = 32

    var body: some View {
        Circle()
            .fill(LinearGradient(colors: [Color.Brand.blue, Color.Brand.cyan], startPoint: .topLeading, endPoint: .bottomTrailing))
            .frame(width: size, height: size)
            .overlay(
                // Sized to the circle, not the text size setting.
                Text(text).font(.system(size: size * 0.38, weight: .semibold)).foregroundStyle(.white).lineLimit(1)
            )
            .accessibilityHidden(true)
    }
}

/// Countdown for a verification code, drawn in the PassAuth shield gradient.
struct TotpRing: View {
    let remaining: Int
    let period: Int
    var size: CGFloat = 28

    var body: some View {
        let low = remaining <= 5
        let fraction = Double(remaining) / Double(max(period, 1))
        ZStack {
            Circle().stroke(Color.paLine, lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(low ? AnyShapeStyle(Color.paDanger) : AnyShapeStyle(LinearGradient(colors: [Color.Brand.blue, Color.Brand.cyan], startPoint: .top, endPoint: .bottom)),
                        style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text("\(remaining)").font(.system(size: size * 0.36, weight: .semibold).monospacedDigit()).foregroundStyle(low ? Color.paDanger : Color.paMuted)
        }
        .frame(width: size, height: size)
        .accessibilityElement()
        .accessibilityLabel("\(remaining) seconds left")
    }
}

/// Strength scales of the web vault: master passwords (`ui.tsx` `strength`: Weak < 50 bits,
/// Fair < 65, Good < 80, else Strong) and generated / item passwords (the generator's scale).
enum StrengthScale {
    case masterPassword, generated

    func level(_ bits: Double) -> (label: String, level: Int) {
        let (fair, good, strong): (Double, Double, Double) = self == .masterPassword ? (AccountSecurityLogic.weakBits, 65, 80) : (40, 60, 80)
        return bits < fair ? ("Weak", 1) : bits < good ? ("Fair", 2) : bits < strong ? ("Good", 3) : ("Strong", 4)
    }
}

/// Password strength from the core's estimate (bits of entropy), same thresholds as the web vault.
struct StrengthMeter: View {
    let password: String
    /// Keep the meter's height while empty (the layout doesn't jump on the first key).
    var reserveSpace = false
    var scale = StrengthScale.generated

    var body: some View {
        if password.isEmpty && reserveSpace {
            VStack(alignment: .leading, spacing: 4) {
                Capsule().fill(Color.paLine).frame(height: 4)
                Text("Strength").font(.caption).foregroundStyle(Color.paMuted)
            }
            .accessibilityHidden(true)
        } else if !password.isEmpty {
            let (label, level) = scale.level(estimateBits(password: password))
            let color: Color = level == 1 ? .paDanger : level == 2 ? (scale == .masterPassword ? .paWarn : .paAccent) : .paOk
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 4) {
                    ForEach(0..<4, id: \.self) { i in
                        Capsule().fill(i < level ? color : Color.paLine).frame(height: 4)
                    }
                }
                Text("Strength: \(label)").font(.caption).foregroundStyle(Color.paMuted)
            }
            .accessibilityElement(children: .combine)
        }
    }
}

// MARK: Inputs

/// A labelled text box: the label sits above the box, never inside it.
struct LabeledInput: View {
    let label: String
    @Binding var text: String
    var prompt: String? = nil
    var mono = false
    var keyboard: UIKeyboardType = .default
    var content: UITextContentType? = nil
    var autocap: TextInputAutocapitalization = .sentences
    /// No autocorrection (addresses, keys, user names).
    var plain: Bool { mono || keyboard == .URL || keyboard == .emailAddress || content == .username }
    var multiline = false
    var identifier: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(Color.paMuted)
            Group {
                if multiline {
                    TextField("", text: $text, prompt: prompt.map { Text($0) }, axis: .vertical).lineLimit(3...12)
                } else {
                    TextField("", text: $text, prompt: prompt.map { Text($0) })
                }
            }
            .font(mono ? .body.monospaced() : .body)
            .keyboardType(keyboard)
            .textContentType(content)
            .textInputAutocapitalization(autocap)
            .autocorrectionDisabled(plain)
            .accessibilityLabel(label)
            .accessibilityIdentifier(identifier ?? label)
        }
        .padding(.vertical, 2)
    }
}

/// Password-style input with reveal, optional generate button and the label above the box.
struct SecretInput: View {
    let label: String
    @Binding var text: String
    var mono = true
    var content: UITextContentType? = .password
    var onGenerate: (() -> Void)? = nil
    var identifier: String? = nil
    @State private var reveal = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(Color.paMuted)
            HStack(spacing: 10) {
                Group {
                    if reveal {
                        TextField("", text: $text).font(mono ? .body.monospaced() : .body)
                    } else {
                        SecureField("", text: $text)
                    }
                }
                .textContentType(content)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .accessibilityLabel(label)
                .accessibilityIdentifier(identifier ?? label)
                Button { reveal.toggle() } label: {
                    Image(systemName: reveal ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(reveal ? "Hide \(label.lowercased())" : "Show \(label.lowercased())")
                if let onGenerate {
                    Button(action: onGenerate) { Image(systemName: "dice") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Generate password")
                }
            }
        }
        .padding(.vertical, 2)
    }
}

/// A boxed input for the sign-in screens (outside of forms).
struct AuthField: View {
    let label: String
    @Binding var text: String
    var secure = false
    var mono = false
    var keyboard: UIKeyboardType = .default
    var content: UITextContentType? = nil
    var prompt: String? = nil
    var submit: (() -> Void)? = nil
    @State private var reveal = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.subheadline.weight(.medium)).foregroundStyle(Color.paInk)
            HStack {
                Group {
                    if secure && !reveal {
                        SecureField("", text: $text, prompt: prompt.map { Text($0) })
                    } else {
                        TextField("", text: $text, prompt: prompt.map { Text($0) })
                            .font(mono ? .body.monospaced() : .body)
                    }
                }
                .keyboardType(keyboard)
                .textContentType(content)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.go)
                .onSubmit { submit?() }
                .accessibilityLabel(label)
                .accessibilityIdentifier(label)
                if secure {
                    Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye").foregroundStyle(Color.paMuted) }
                        .accessibilityLabel(reveal ? "Hide \(label.lowercased())" : "Show \(label.lowercased())")
                }
            }
            .padding(.horizontal, 14)
            .frame(minHeight: 48)
            .background(Color.paSurface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.paLine))
        }
    }
}

/// Full-width brand button.
struct PrimaryButton: View {
    let title: String
    var busy = false
    var enabled = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if busy { ProgressView().tint(.white) }
                Text(title).fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity, minHeight: 30)
        }
        .buttonStyle(.borderedProminent)
        .tint(Color.paAccentFill)
        .controlSize(.large)
        .disabled(!enabled || busy)
    }
}

struct Notice: View {
    enum Kind { case info, ok, error }
    let text: String
    var kind: Kind = .info

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: kind == .error ? "exclamationmark.triangle.fill" : kind == .ok ? "checkmark.circle.fill" : "info.circle.fill")
            Text(text).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .font(.subheadline)
        .foregroundStyle(kind == .error ? Color.paDanger : kind == .ok ? Color.paOk : Color.paAccentInk)
        .padding(12)
        .background(kind == .error ? Color.paDanger.opacity(0.12) : kind == .ok ? Color.paOk.opacity(0.12) : Color.paAccentSoft, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .combine)
    }
}

/// Error text under a form.
struct ErrorText: View {
    let text: String?
    var body: some View {
        if let text {
            Text(text).font(.subheadline).foregroundStyle(Color.paDanger).frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityIdentifier("error")
        }
    }
}

func hostOf(_ server: String) -> String { UrlMatcher.parse(server)?.host ?? server }

func formatDate(_ unixSeconds: Int64) -> String {
    Date(timeIntervalSince1970: TimeInterval(unixSeconds)).formatted(date: .abbreviated, time: .shortened)
}

func secondsLabel(_ s: Int) -> String {
    s < 60 ? "\(s) seconds" : "\(s / 60) minute\(s >= 120 ? "s" : "")"
}

/// Centered, scrollable column for the sign-in screens.
struct AuthFrame<Content: View>: View {
    let title: String
    var subtitle: String? = nil
    @ViewBuilder let content: Content

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                LogoMark(height: 60).padding(.top, 36)
                Text(title).font(.title2.weight(.semibold)).multilineTextAlignment(.center).foregroundStyle(Color.paInk)
                    .accessibilityAddTraits(.isHeader)
                if let subtitle {
                    Text(subtitle).font(.subheadline).foregroundStyle(Color.paMuted).multilineTextAlignment(.center)
                }
                VStack(spacing: 14) { content }.padding(.top, 4)
            }
            .frame(maxWidth: 480)
            .padding(.horizontal, 24)
            .padding(.bottom, 32)
            .frame(maxWidth: .infinity)
        }
        .scrollDismissesKeyboard(.interactively)
        .background(Color.paBackground.ignoresSafeArea())
    }
}
