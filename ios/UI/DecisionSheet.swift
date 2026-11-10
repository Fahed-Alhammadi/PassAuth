import SwiftUI

// The anatomy every PassAuth prompt follows ("decision sheet"), in the iOS idiom:
//   1. brand bar: the logo and "PassAuth" at the leading edge, close at the trailing edge;
//   2. context row (`PromptHeader`): what is being decided and for which site, leading-aligned;
//   3. choices: one grouped section of rows with a radio mark (`ChoiceRow`);
//   4. verification (master password) right above the actions;
//   5. actions (`PromptScaffold`'s bar): one filled button, quiet text buttons on a row
//      beneath it, errors just above them. The bar stays put while the content scrolls.

#if os(iOS)

/// The brand bar of a prompt: logo and name leading, `close` trailing (when the prompt can be closed).
struct PromptBar: ViewModifier {
    var closeLabel = "Cancel"
    /// Text instead of the close mark (e.g. "Done").
    var closeText: String? = nil
    var closeIdentifier = "promptClose"
    var close: (() -> Void)? = nil

    func body(content: Content) -> some View {
        content
            .navigationBarTitleDisplayMode(.inline)
            .paNavBar()
            .toolbar {
                brand
                if let close {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button(action: close) {
                            if let closeText {
                                Text(closeText).fontWeight(.semibold)
                            } else {
                                Image(systemName: "xmark").fontWeight(.medium)
                            }
                        }
                        .accessibilityLabel(closeText ?? closeLabel)
                        .accessibilityIdentifier(closeIdentifier)
                    }
                }
            }
    }

    @ToolbarContentBuilder private var brand: some ToolbarContent {
        // A mark, not a button: no glass capsule around it.
        if #available(iOS 26.0, *) {
            ToolbarItem(placement: .topBarLeading) { BrandMark() }.sharedBackgroundVisibility(.hidden)
        } else {
            ToolbarItem(placement: .topBarLeading) { BrandMark() }
        }
    }
}

extension View {
    /// The brand bar of a prompt (inside a `NavigationStack`); without `close` just the brand.
    func promptBar(closeLabel: String = "Cancel", closeText: String? = nil, closeIdentifier: String = "promptClose", close: (() -> Void)? = nil) -> some View {
        modifier(PromptBar(closeLabel: closeLabel, closeText: closeText, closeIdentifier: closeIdentifier, close: close))
    }

    /// A list row without a card behind it (the context row, notes between sections).
    func promptPlainRow() -> some View {
        listRowInsets(EdgeInsets(top: PA.Space.xs, leading: PA.Space.xs, bottom: PA.Space.xs, trailing: PA.Space.xs))
            .listRowBackground(Color.clear)
            .listRowSeparator(.hidden)
    }
}

/// A prompt: grouped sections that scroll, with the actions pinned beneath them.
struct PromptScaffold<Content: View, Actions: View>: View {
    /// Shown between the content and the actions.
    var error: String? = nil
    @ViewBuilder let content: Content
    @ViewBuilder let actions: Actions

    var body: some View {
        List { content }
            .listStyle(.insetGrouped)
            .listSectionSpacing(.compact)
            .contentMargins(.top, PA.Space.s, for: .scrollContent)
            .paList()
            .scrollDismissesKeyboard(.interactively)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                VStack(spacing: PA.Space.s) {
                    ErrorText(text: error)
                    actions
                }
                .frame(maxWidth: 480)
                .padding(.horizontal, PA.Space.l)
                .padding(.top, PA.Space.m)
                .padding(.bottom, PA.Space.s)
                .frame(maxWidth: .infinity)
                .background(Color.paBackground)
            }
    }
}

/// The quiet actions under the primary button: text buttons on one row (stacked when large
/// text doesn't fit).
struct QuietActions<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: PA.Space.xl) { content }
            VStack(spacing: 0) { content }
        }
        .buttonStyle(.borderless)
        .font(.subheadline.weight(.medium))
    }
}

/// One quiet action (a text button with a full-size touch target).
struct QuietButton: View {
    let title: String
    var symbol: String? = nil
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if let symbol { Image(systemName: symbol) }
                Text(title)
            }
            .frame(minWidth: 44, minHeight: 44)
            .contentShape(Rectangle())
        }
    }
}

/// A row of a choice list: tile, title, detail and the radio mark of the selected row.
struct ChoiceRow: View {
    @Environment(\.dynamicTypeSize) private var typeSize
    let title: String
    var detail = ""
    /// The tile shows this symbol instead of the title's first letter.
    var symbol: String? = nil
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: PA.Space.m) {
                // Large text: the words get the room, and nothing is cut off.
                if !typeSize.isAccessibilitySize { InitialTile(text: title, symbol: symbol) }
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).foregroundStyle(Color.paInk)
                    if !detail.isEmpty { Text(detail).font(.subheadline).foregroundStyle(Color.paMuted) }
                }
                .lineLimit(typeSize.isAccessibilitySize ? nil : 2)
                Spacer(minLength: PA.Space.s)
                SelectionMark(selected: selected)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}

/// A label above its value, for the details a prompt shows (what will be saved). VoiceOver
/// reads it as one element: the label, then `spoken` (or the value).
struct DetailRow<Trailing: View>: View {
    let label: String
    let value: String
    var mono = false
    var muted = false
    /// What VoiceOver says instead of the value (e.g. "hidden" for a masked password).
    var spoken: String? = nil
    var identifier: String? = nil
    @ViewBuilder let trailing: Trailing

    var body: some View {
        HStack(spacing: PA.Space.m) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.caption).foregroundStyle(Color.paMuted)
                Text(value).font(mono ? .body.monospaced() : .body).foregroundStyle(muted ? Color.paMuted : Color.paInk)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(label)
            .accessibilityValue(spoken ?? value)
            .accessibilityIdentifier(identifier ?? label)
            Spacer(minLength: 0)
            trailing
        }
    }
}

extension DetailRow where Trailing == EmptyView {
    init(label: String, value: String, mono: Bool = false, muted: Bool = false, spoken: String? = nil, identifier: String? = nil) {
        self.init(label: label, value: value, mono: mono, muted: muted, spoken: spoken, identifier: identifier) { EmptyView() }
    }
}

#endif
