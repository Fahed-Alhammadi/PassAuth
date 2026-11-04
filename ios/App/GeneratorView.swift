import PassAuthCore
import PassAuthKit
import SwiftUI

/// Password and passphrase generator (options go to the core as JSON). The options are kept
/// in the shared settings (`Settings.generator`), so AutoFill's password generation uses them.
struct GeneratorTab: View {
    @Environment(AppModel.self) private var model
    @State private var g = GeneratorSettings()
    @State private var loaded = false
    @State private var value = ""
    @State private var seed = 0

    private var passphrase: Bool { g.passphrase }

    private var options: String {
        passphrase ? PasswordGeneration.passphraseJSON(g) : PasswordGeneration.passwordJSON(g)
    }

    private var lengthValue: Binding<Double> {
        Binding(get: { Double(g.length) }, set: { g.length = Int($0) })
    }

    private var wordsValue: Binding<Double> {
        Binding(get: { Double(g.words) }, set: { g.words = Int($0) })
    }

    @ViewBuilder
    private var actions: some View {
        Button { model.copy(value, passphrase ? "Passphrase" : "Password") } label: {
            Text("Copy").lineLimit(1).frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
        Button { seed += 1 } label: {
            Text("Regenerate").lineLimit(1).frame(maxWidth: .infinity)
        }
        .buttonStyle(.bordered)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Type", selection: $g.passphrase) {
                        Text("Password").tag(false)
                        Text("Passphrase").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                }
                Section {
                    Text(value)
                        .speechSpellsOutCharacters()
                        .font(.system(.title2, design: .monospaced))
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("generated")
                    StrengthMeter(password: value)
                    // Side by side, or stacked when large text doesn't fit.
                    ViewThatFits(in: .horizontal) {
                        HStack(spacing: 12) { actions.fixedSize(horizontal: false, vertical: true) }
                        VStack(spacing: 10) { actions }
                    }
                    .controlSize(.large)
                }
                .paRow()
                Section("Options") {
                    if passphrase {
                        VStack(alignment: .leading) {
                            Text("Words: \(g.words)")
                            Slider(value: wordsValue, in: 3...12, step: 1).accessibilityLabel("Words")
                        }
                        LabeledInput(label: "Word separator", text: Binding(get: { g.separator }, set: { g.separator = String($0.prefix(3)) }), autocap: .never)
                        Toggle("Capitalize words", isOn: $g.capitalize)
                        Toggle("Include a number", isOn: $g.includeNumber)
                    } else {
                        VStack(alignment: .leading) {
                            Text("Length: \(g.length)")
                            Slider(value: lengthValue, in: 8...64, step: 1).accessibilityLabel("Length")
                        }
                        Toggle("Uppercase (A-Z)", isOn: guarded(\.uppercase))
                        Toggle("Lowercase (a-z)", isOn: guarded(\.lowercase))
                        Toggle("Numbers (0-9)", isOn: guarded(\.digits))
                        Toggle("Symbols (!@#…)", isOn: guarded(\.symbols))
                        Toggle(isOn: $g.avoidAmbiguous) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Avoid ambiguous characters")
                                Text("Leaves out characters that look alike, such as l, 1, O and 0.").font(.footnote).foregroundStyle(Color.paMuted)
                            }
                        }
                    }
                }
                .paRow()
            }
            .paList()
            .navigationTitle("Generator")
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { LogoMark(height: 26) }
                ToolbarItem(placement: .topBarTrailing) { AccountMenu() }
            }
            .task(id: "\(options)|\(seed)") { regenerate() }
            .task(id: g) { await persist() }
            .onAppear(perform: load)
        }
    }

    /// At least one character set stays on.
    private func guarded(_ key: WritableKeyPath<GeneratorSettings, Bool>) -> Binding<Bool> {
        Binding(get: { g[keyPath: key] }, set: { on in
            let others = [g.uppercase, g.lowercase, g.digits, g.symbols].filter { $0 }.count - (g[keyPath: key] ? 1 : 0)
            g[keyPath: key] = on || others == 0
        })
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        g = Self.migrated(model.state.settings.generator)
    }

    /// Saved shortly after the last change (a slider drag doesn't write the settings file each step).
    private func persist() async {
        guard loaded, g != model.state.settings.generator else { return }
        try? await Task.sleep(for: .milliseconds(400))
        guard !Task.isCancelled else { return }
        let next = g
        await model.repo.updateSettings { $0.generator = next }
    }

    /// Options from before they were shared with AutoFill (app-only user defaults), once.
    private static func migrated(_ current: GeneratorSettings) -> GeneratorSettings {
        let d = UserDefaults.standard
        let keys = ["passphrase", "length", "upper", "lower", "digits", "symbols", "avoidAmbiguous", "words", "separator", "capitalize", "number"].map { "generator.\($0)" }
        guard keys.contains(where: { d.object(forKey: $0) != nil }) else { return current }
        var g = current
        if d.object(forKey: "generator.passphrase") != nil { g.passphrase = d.bool(forKey: "generator.passphrase") }
        if d.object(forKey: "generator.length") != nil { g.length = min(max(Int(d.double(forKey: "generator.length")), 8), 128) }
        if d.object(forKey: "generator.upper") != nil { g.uppercase = d.bool(forKey: "generator.upper") }
        if d.object(forKey: "generator.lower") != nil { g.lowercase = d.bool(forKey: "generator.lower") }
        if d.object(forKey: "generator.digits") != nil { g.digits = d.bool(forKey: "generator.digits") }
        if d.object(forKey: "generator.symbols") != nil { g.symbols = d.bool(forKey: "generator.symbols") }
        if d.object(forKey: "generator.avoidAmbiguous") != nil { g.avoidAmbiguous = d.bool(forKey: "generator.avoidAmbiguous") }
        if d.object(forKey: "generator.words") != nil { g.words = min(max(Int(d.double(forKey: "generator.words")), 3), 20) }
        if let s = d.string(forKey: "generator.separator") { g.separator = String(s.prefix(3)) }
        if d.object(forKey: "generator.capitalize") != nil { g.capitalize = d.bool(forKey: "generator.capitalize") }
        if d.object(forKey: "generator.number") != nil { g.includeNumber = d.bool(forKey: "generator.number") }
        keys.forEach(d.removeObject)
        return g
    }

    private func regenerate() {
        let o = options
        value = (try? passphrase ? generatePassphrase(optionsJson: o) : generatePassword(optionsJson: o)) ?? ""
    }
}
