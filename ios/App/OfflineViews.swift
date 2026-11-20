import Network
import PassAuthCore
import PassAuthKit
import SwiftUI

// Offline changes (waiting to sync) in the app: the status in the vault list, the marker on
// rows, the item page's notice with "Discard this change", and the decision sheet for changes
// made on another device meanwhile. The rules are in ios/Shared/OfflineChanges.swift.

/// Watches the network (NWPathMonitor): the repository learns when the OS says it is offline,
/// and when the connection comes back the vault syncs, which sends what waits.
@MainActor
final class NetworkWatch {
    private let monitor = NWPathMonitor()
    private weak var repo: VaultRepository?
    private var wasAvailable: Bool?

    init(repo: VaultRepository) {
        self.repo = repo
        monitor.pathUpdateHandler = { [weak self] path in
            let available = path.status == .satisfied
            Task { @MainActor in self?.changed(available) }
        }
        monitor.start(queue: DispatchQueue(label: "io.passauth.app.network"))
    }

    private func changed(_ available: Bool) {
        guard let repo else { return }
        let before = wasAvailable
        wasAvailable = available
        repo.networkAvailable = available
        // Back online: sync (its checks first), then the sender runs.
        if available, before == false, repo.isUnlocked {
            Task { try? await repo.sync() }
        }
    }
}

/// The marker a row or an item page shows for an item with a waiting change.
struct OfflineMarker: View {
    let mark: OfflineMark

    var body: some View {
        Label {
            Text(mark.label).lineLimit(2)
        } icon: {
            Image(systemName: symbol)
        }
        .labelStyle(TightLabel())
        .font(.caption.weight(.medium))
        .foregroundStyle(color)
        .accessibilityIdentifier("offline.marker")
    }

    private var symbol: String {
        switch mark.state {
        case .waiting: "arrow.triangle.2.circlepath"
        case .held: "exclamationmark.circle"
        case .conflict: "exclamationmark.triangle.fill"
        }
    }

    private var color: Color {
        switch mark.state {
        case .waiting: Color.paMuted
        case .held: Color.paWarn
        case .conflict: Color.paDanger
        }
    }
}

/// The vault list's line about waiting changes ("N changes waiting to sync" / "N changes need
/// your decision"); with conflicts it opens the first one.
struct OfflineStatusSection: View {
    @Environment(AppModel.self) private var model
    @State private var deciding: OfflineChange?

    var body: some View {
        let changes = model.repo.offlineChanges
        if model.repo.offlineUnreadable {
            Section {
                Notice(text: OfflineText.cantOpen, kind: .error)
                    .listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
                    .accessibilityIdentifier("offline.unreadable")
            }
        } else if let text = OfflineText.status(changes) {
            let conflicts = model.repo.offlineConflicts
            Section {
                Button {
                    if let first = conflicts.first { deciding = first }
                } label: {
                    Notice(text: text + (conflicts.isEmpty ? "." : ". Tap to decide."), kind: conflicts.isEmpty ? .info : .error)
                }
                .buttonStyle(.plain)
                .disabled(conflicts.isEmpty)
                .listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
                .accessibilityIdentifier("offline.status")
            }
            .sheet(item: $deciding) { OfflineConflictSheet(changeId: $0.id) }
        }
    }
}

/// On an item page with a waiting change: what it is, "Decide" for a conflict, and "Discard this change".
struct OfflineItemSection: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let entry: Entry
    let mark: OfflineMark
    @State private var confirmDiscard = false
    @State private var deciding = false

    var body: some View {
        Section {
            Notice(text: explanation, kind: mark.state == .waiting ? .info : .error)
                .listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
                .accessibilityIdentifier("offline.itemNotice")
            if mark.state == .conflict {
                Button { deciding = true } label: { Label("Decide which version to keep", systemImage: "arrow.left.arrow.right") }
                    .paRow()
                    .accessibilityIdentifier("offline.decide")
            }
            Button(role: .destructive) { confirmDiscard = true } label: { Label(OfflineText.discard, systemImage: "arrow.uturn.backward").foregroundStyle(Color.paDanger) }
                .paRow()
                .accessibilityIdentifier("offline.discard")
        }
        .confirmationDialog(OfflineText.discardTitle, isPresented: $confirmDiscard, titleVisibility: .visible) {
            Button(OfflineText.discard, role: .destructive) {
                let created = mark.kind == .create
                model.run {
                    try await model.repo.discardOfflineChange(entry.id)
                    model.notify("Change discarded.")
                    if created { dismiss() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(OfflineText.discardMessage)
        }
        .sheet(isPresented: $deciding) { OfflineConflictSheet(changeId: mark.changeId) }
    }

    private var explanation: String {
        switch mark.state {
        case .waiting:
            switch mark.kind {
            case .create: "Saved on this device. It will be added to your vault when you're back online."
            case .edit: "Your changes are saved on this device and will sync when you're back online."
            case .trash: "Moved to the trash on this device. This syncs when you're back online."
            }
        case .held: OfflineText.held(mark.reason)
        case .conflict: (mark.reason ?? OfflineText.changedText) + " Choose which version to keep. Nothing is sent until you do."
        }
    }
}

/// The decision sheet "Changed on another device": both versions with the fields that differ
/// marked (passwords hidden until shown), then the choices the conflict allows.
struct OfflineConflictSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let changeId: String
    @State private var choice: OfflineChoice?
    @State private var shown: Set<String> = []
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            if let change = model.repo.offlineChanges.first(where: { $0.id == changeId }) {
                content(change)
            } else {
                Color.paBackground.onAppear { dismiss() }
            }
        }
        .interactiveDismissDisabled(busy)
    }

    @ViewBuilder
    private func content(_ c: OfflineChange) -> some View {
        let other = model.repo.serverEntry(for: c)
        let kind = OfflineQueue.conflictKind(c, serverHasItem: other != nil)
        // A trash carries no item: the sheet shows the other device's version alone; an edit of
        // a deleted item shows this device's alone.
        let mine = c.kind == .trash ? other?.item : c.decodedItem
        let fields = OfflineQueue.compare(mine: mine, theirs: c.kind == .trash ? mine : other?.item)
        let choices = OfflineQueue.choices(kind)
        let name = (mine?.name).flatMap { $0.isEmpty ? nil : $0 } ?? other?.item.name ?? "Untitled"
        PromptScaffold(error: error) {
            Section {
                PromptHeader(symbol: "arrow.triangle.branch", title: OfflineText.conflict, subtitle: subtitle(kind, name: name))
                    .promptPlainRow()
            }
            if kind == .deleted {
                Section {
                    Text("This item was deleted on another device after you changed it here. Save your version as a new item, or discard it.")
                        .foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
                }
                .paRow()
            } else if kind == .trash {
                Section {
                    Text("You moved this item to the trash on this device, but it was changed on another device meanwhile.")
                        .foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
                }
                .paRow()
            }
            if !fields.isEmpty {
                Section {
                    ForEach(fields) { f in fieldRow(f, kind: kind) }
                } header: {
                    Text(kind == .deleted ? "Your version" : kind == .trash ? "The other device's version" : "This device · Other device")
                } footer: {
                    if fields.contains(where: \.differs) && kind == .changed {
                        Text("Fields marked with a dot differ.")
                    }
                }
                .paRow()
            }
            Section {
                ForEach(choices, id: \.self) { ch in
                    ChoiceRow(title: ch.title, detail: detail(ch), symbol: symbol(ch), selected: choice == ch) { choice = ch }
                        .accessibilityIdentifier("offline.choice.\(ch.rawValue)")
                }
            }
            .paRow()
        } actions: {
            PrimaryButton(title: busy ? "Saving…" : (choice?.title ?? "Choose an option"), busy: busy, enabled: choice != nil,
                          destructive: choice == .discardMine || choice == .trashAnyway, action: { apply(c) })
                .accessibilityIdentifier("offline.apply")
            QuietActions {
                QuietButton(title: "Decide later") { dismiss() }.disabled(busy)
            }
        }
        .promptBar(closeLabel: "Decide later", close: busy ? nil : { dismiss() })
    }

    @ViewBuilder
    private func fieldRow(_ f: OfflineField, kind: OfflineConflictKind) -> some View {
        let reveal = !f.secret || shown.contains(f.label)
        let hide = { (s: String) in s.isEmpty ? "—" : (reveal ? s : String(repeating: "•", count: 8)) }
        HStack(alignment: .top, spacing: PA.Space.m) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    if f.differs && kind == .changed {
                        Circle().fill(Color.paAccent).frame(width: 7, height: 7).accessibilityHidden(true)
                    }
                    Text(f.label).font(.caption).foregroundStyle(f.differs && kind == .changed ? Color.paAccentInk : Color.paMuted)
                }
                if kind != .changed {
                    Text(hide(f.mine)).foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
                } else {
                    ViewThatFits(in: .horizontal) {
                        HStack(alignment: .top, spacing: PA.Space.m) {
                            version("This device", hide(f.mine))
                            version("Other device", hide(f.theirs))
                        }
                        VStack(alignment: .leading, spacing: PA.Space.xs) {
                            version("This device", hide(f.mine))
                            version("Other device", hide(f.theirs))
                        }
                    }
                }
            }
            Spacer(minLength: 0)
            if f.secret {
                Button {
                    if shown.contains(f.label) { shown.remove(f.label) } else { shown.insert(f.label) }
                } label: {
                    Image(systemName: reveal ? "eye.slash" : "eye").frame(minWidth: 44, minHeight: 44)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(reveal ? "Hide \(f.label.lowercased())" : "Show \(f.label.lowercased())")
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityValue(f.differs && kind == .changed ? "Differs" : "")
    }

    private func version(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(.caption2).foregroundStyle(Color.paMuted)
            Text(value).font(.subheadline).foregroundStyle(Color.paInk).fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func subtitle(_ kind: OfflineConflictKind, name: String) -> String {
        switch kind {
        case .changed: "“\(name)” was changed here and on another device."
        case .deleted: "“\(name)” was deleted on another device."
        case .trash: "“\(name)” was changed on another device."
        }
    }

    private func detail(_ c: OfflineChoice) -> String {
        switch c {
        case .keepMine: "Your version replaces the other device's."
        case .keepOther: "Your change on this device is dropped."
        case .keepBoth: "Yours is saved as a new item named “… (offline copy)”."
        case .saveAsNew: "Your version is saved as a new item."
        case .discardMine: "Your change on this device is dropped."
        case .trashAnyway: "The other device's version goes to the trash."
        }
    }

    private func symbol(_ c: OfflineChoice) -> String {
        switch c {
        case .keepMine: "iphone"
        case .keepOther: "arrow.down.circle"
        case .keepBoth: "square.on.square"
        case .saveAsNew: "plus.square.on.square"
        case .discardMine: "xmark.circle"
        case .trashAnyway: "trash"
        }
    }

    private func apply(_ c: OfflineChange) {
        guard let choice, !busy else { return }
        busy = true
        error = nil
        Task {
            do {
                try await model.repo.resolveOffline(c.id, choice)
                model.notify(done(choice))
                dismiss()
            } catch {
                self.error = errorMessage(error)
            }
            busy = false
        }
    }

    private func done(_ c: OfflineChoice) -> String {
        switch c {
        case .keepMine: "Your version was saved."
        case .keepOther, .discardMine: "Your change was discarded."
        case .keepBoth, .saveAsNew: "Your version was saved as a new item."
        case .trashAnyway: "Moved to trash."
        }
    }
}
