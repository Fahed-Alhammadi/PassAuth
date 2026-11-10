import PassAuthCore
import PassAuthKit
import SwiftUI

struct ListFilter: Equatable {
    enum Scope: Hashable { case all, favorites, trash }
    var scope = Scope.all
    var kind: ItemKind?
    /// nil = any, "" = no folder.
    var folder: String?
    var vaultId: String?

    var active: Bool { scope != .all || kind != nil || folder != nil || vaultId != nil }
}

/// List row data, like the extension's `ItemSummary`.
struct ItemSummary: Identifiable {
    let entry: Entry
    let name: String
    let subtitle: String
    let host: String
    let url: String
    var id: String { entry.id }
    var item: Item { entry.item }

    init(_ e: Entry) {
        entry = e
        let i = e.item
        host = i.siteHost
        name = i.name.isEmpty ? "Untitled" : i.name
        if let u = i.login?.username, !u.isEmpty {
            subtitle = u
        } else if !host.isEmpty {
            subtitle = host
        } else if let n = i.card?.number, n.count >= 4 {
            subtitle = "•••• \(n.suffix(4))"
        } else {
            subtitle = String((i.notes.split(separator: "\n").first ?? "").prefix(50))
        }
        let web = i.login?.urls.first { $0.match != .regex && $0.url.range(of: "^https?://", options: [.regularExpression, .caseInsensitive]) != nil }?.url
        url = web ?? (host.isEmpty ? "" : "https://\(host)")
    }
}

/// What the editor sheet edits.
enum EditTarget: Identifiable {
    case new(ItemKind)
    case edit(String)
    var id: String {
        switch self {
        case .new(let k): "new:\(k.rawValue)"
        case .edit(let id): "edit:\(id)"
        }
    }
}

struct VaultTab: View {
    @Environment(AppModel.self) private var model
    @State private var path: [String] = []
    @State private var query = ""
    @State private var filter = ListFilter()
    @State private var editing: EditTarget?

    var body: some View {
        NavigationStack(path: $path) {
            VaultList(query: $query, filter: $filter, editing: $editing)
                .navigationDestination(for: String.self) { id in
                    ItemView(id: id) { editing = .edit(id) }
                }
        }
        .sheet(item: $editing) { target in
            EditSheet(target: target) { savedId in
                if case .new = target, let savedId { path = [savedId] }
            }
        }
    }
}

struct EditSheet: View {
    @Environment(AppModel.self) private var model
    let target: EditTarget
    let onSaved: (String?) -> Void

    var body: some View {
        switch target {
        case .new(let kind):
            EditView(entry: nil, kind: kind, onSaved: onSaved)
        case .edit(let id):
            if let e = model.repo.vault?.get(id) {
                EditView(entry: e, kind: e.item.kind, onSaved: onSaved)
            }
        }
    }
}

private struct VaultList: View {
    @Environment(AppModel.self) private var model
    @Binding var query: String
    @Binding var filter: ListFilter
    @Binding var editing: EditTarget?
    @State private var trashing: Entry?
    @State private var purging: Entry?
    /// The section of the row that asked (a favorite is listed twice; one row shows the dialog).
    @State private var askingIn = ""

    var body: some View {
        let v = model.repo.vault
        let source = filter.scope == .trash ? (v?.trash ?? []) : (v?.entries ?? [])
        let all = source.map(ItemSummary.init)
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        let found = all.filter { s in
            (q.isEmpty || s.name.lowercased().contains(q) || s.subtitle.lowercased().contains(q) || s.host.contains(q))
                && (filter.kind == nil || s.item.kind == filter.kind)
                && (filter.folder == nil || (s.item.folder ?? "") == filter.folder)
                && (filter.vaultId == nil || s.entry.vaultId == filter.vaultId)
                && (filter.scope != .favorites || s.item.favorite)
        }
        List {
            if v?.offline == true {
                Section {
                    Notice(text: "You're offline. Showing the copy of your vault saved on this device.")
                        .listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
                }
            }
            if filter.active {
                Section {
                    HStack {
                        Image(systemName: "line.3.horizontal.decrease.circle.fill").foregroundStyle(Color.paAccent)
                        Text(filterSummary(v)).font(.subheadline).lineLimit(2)
                        Spacer()
                        Button("Clear") { filter = ListFilter() }.font(.subheadline.weight(.medium))
                    }
                    .paRow()
                }
            }
            if let v {
                if filter.active || !q.isEmpty {
                    let title = filter.scope == .trash ? "Trash" : !q.isEmpty ? "Search results" : "Filtered items"
                    section(title, found)
                    if found.isEmpty {
                        Text(filter.scope == .trash && q.isEmpty ? "The trash is empty." : "No items match. Try another search or clear the filters.")
                            .foregroundStyle(Color.paMuted).listRowBackground(Color.clear)
                    }
                    if filter.scope == .trash && !found.isEmpty {
                        Text("Items in the trash can be restored or deleted for good.").font(.footnote).foregroundStyle(Color.paMuted).listRowBackground(Color.clear)
                    }
                } else if v.entries.isEmpty {
                    ContentUnavailableView {
                        Label("Your vault is empty", systemImage: "lock.shield")
                    } description: {
                        Text("Save your first login and it's encrypted on this device before it reaches your server.")
                    } actions: {
                        Button("New login") { editing = .new(.login) }.buttonStyle(.borderedProminent)
                    }
                    .listRowBackground(Color.clear)
                } else {
                    let favorites = all.filter(\.item.favorite)
                    if !favorites.isEmpty { section("Favorites", favorites) }
                    section("All items", all)
                }
            } else {
                ProgressView().frame(maxWidth: .infinity).listRowBackground(Color.clear)
            }
        }
        .listStyle(.insetGrouped)
        .paList()
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always), prompt: "Search vault")
        .refreshable {
            do { try await model.repo.sync() } catch { model.notify("Sync failed: \(errorMessage(error))") }
        }
        .navigationTitle(filter.scope == .trash ? "Trash" : "Vault")
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .toolbar {
            ToolbarItem(placement: .topBarLeading) { LogoMark(height: 26) }
            ToolbarItemGroup(placement: .topBarTrailing) {
                FilterMenu(filter: $filter)
                Menu {
                    ForEach(ItemKind.allCases) { k in
                        Button { editing = .new(k) } label: { Label(k.label, systemImage: k.symbol) }
                    }
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("New item")
                .accessibilityIdentifier("newItem")
                AccountMenu()
            }
        }
    }

    /// Whether `e` is the entry a confirmation is open for (the dialog hangs off its row).
    private func asking(_ which: Binding<Entry?>, _ e: Entry, in section: String) -> Binding<Bool> {
        Binding(get: { which.wrappedValue?.id == e.id && askingIn == section }, set: { if !$0 { which.wrappedValue = nil } })
    }

    private func filterSummary(_ v: VaultData?) -> String {
        var parts: [String] = []
        switch filter.scope {
        case .favorites: parts.append("Favorites")
        case .trash: parts.append("Trash")
        case .all: break
        }
        if let k = filter.kind { parts.append(k.label) }
        if let f = filter.folder { parts.append(f.isEmpty ? "No folder" : "Folder \(f)") }
        if let id = filter.vaultId { parts.append(v?.vaultName(id) ?? "Vault") }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder
    private func section(_ title: String, _ items: [ItemSummary]) -> some View {
        if !items.isEmpty {
            Section {
                ForEach(items) { s in row(s, in: title) }
            } header: {
                HStack {
                    Text(title)
                    Spacer()
                    Text("\(items.count)")
                }
            }
        }
    }

    private func row(_ s: ItemSummary, in section: String) -> some View {
        let canWrite = model.repo.vault?.canWrite(s.entry) ?? false
        let login = s.item.login
        let trashed = s.entry.deletedAt != nil
        return NavigationLink(value: s.entry.id) {
            ItemRow(summary: s)
        }
        .paRow()
        .swipeActions(edge: .leading, allowsFullSwipe: true) {
            if !trashed, let p = login?.password, !p.isEmpty {
                Button { model.copy(p, "Password") } label: { Label("Copy password", systemImage: "key") }.tint(Color.paAccent)
            }
            if !trashed, let u = login?.username, !u.isEmpty {
                Button { model.copy(u, "Username") } label: { Label("Copy username", systemImage: "person") }.tint(.indigo)
            }
        }
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            if canWrite {
                if trashed {
                    // Not the destructive role: these ask first, the row stays where it is.
                    Button { askingIn = section; purging = s.entry } label: { Label("Delete forever", systemImage: "trash.slash") }.tint(Color.paDanger)
                    Button {
                        model.run {
                            try await model.repo.restoreItem(s.entry)
                            model.notify("Item restored.")
                        }
                    } label: { Label("Restore", systemImage: "arrow.uturn.backward") }.tint(Color.paOk)
                } else {
                    Button { askingIn = section; trashing = s.entry } label: { Label("Move to trash", systemImage: "trash") }.tint(Color.paDanger)
                    Button {
                        model.run { try await model.repo.setFavorite(s.entry, !s.item.favorite) }
                    } label: {
                        Label(s.item.favorite ? "Remove from favorites" : "Add to favorites", systemImage: s.item.favorite ? "star.slash" : "star")
                    }.tint(.orange)
                }
            }
        }
        .confirmationDialog("Move to trash?", isPresented: asking($trashing, s.entry, in: section), titleVisibility: .visible) {
            Button("Move to trash", role: .destructive) {
                model.run {
                    try await model.repo.trashItem(s.entry)
                    model.notify("Moved to trash.")
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("“\(s.name)” can be restored from the trash.")
        }
        .confirmationDialog("Delete forever?", isPresented: asking($purging, s.entry, in: section), titleVisibility: .visible) {
            Button("Delete forever", role: .destructive) {
                model.run {
                    try await model.repo.purgeItem(s.entry)
                    model.notify("Item deleted.")
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("“\(s.name)” will be deleted for good. This can't be undone.")
        }
        .contextMenu {
            if !trashed {
                if let u = login?.username, !u.isEmpty { Button { model.copy(u, "Username") } label: { Label("Copy username", systemImage: "person") } }
                if let p = login?.password, !p.isEmpty { Button { model.copy(p, "Password") } label: { Label("Copy password", systemImage: "key") } }
                if let t = login?.totp, !t.trimmingCharacters(in: .whitespaces).isEmpty {
                    Button { model.copyTotp(t) } label: { Label("Copy verification code", systemImage: "clock") }
                }
                if !s.url.isEmpty { Button { model.open(s.url) } label: { Label("Open \(s.host)", systemImage: "safari") } }
                if canWrite {
                    Divider()
                    Button { editing = .edit(s.entry.id) } label: { Label("Edit", systemImage: "pencil") }
                    Button { model.run { try await model.repo.setFavorite(s.entry, !s.item.favorite) } } label: {
                        Label(s.item.favorite ? "Remove from favorites" : "Add to favorites", systemImage: s.item.favorite ? "star.slash" : "star")
                    }
                    Button(role: .destructive) { askingIn = section; trashing = s.entry } label: { Label("Move to trash", systemImage: "trash") }
                }
            } else if canWrite {
                Button {
                    model.run {
                        try await model.repo.restoreItem(s.entry)
                        model.notify("Item restored.")
                    }
                } label: { Label("Restore", systemImage: "arrow.uturn.backward") }
                Button(role: .destructive) { askingIn = section; purging = s.entry } label: { Label("Delete forever", systemImage: "trash.slash") }
            }
        }
    }
}

struct ItemRow: View {
    @Environment(\.dynamicTypeSize) private var typeSize
    let summary: ItemSummary

    var body: some View {
        // Large text: the name and the user name wrap instead of being cut off.
        let lines: Int? = typeSize.isAccessibilitySize ? nil : 1
        HStack(spacing: PA.Space.m) {
            SiteIcon(host: summary.host, name: summary.name, kind: summary.item.kind)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(summary.name).foregroundStyle(Color.paInk).lineLimit(lines)
                    if summary.item.favorite {
                        Image(systemName: "star.fill").font(.caption2).foregroundStyle(Color.paAccent).accessibilityLabel("Favorite")
                    }
                }
                if !summary.subtitle.isEmpty {
                    Text(summary.subtitle).font(.subheadline).foregroundStyle(Color.paMuted).lineLimit(lines)
                }
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("item:\(summary.name)")
    }
}

private struct FilterMenu: View {
    @Environment(AppModel.self) private var model
    @Binding var filter: ListFilter

    var body: some View {
        let v = model.repo.vault
        let folders = v?.folders ?? []
        Menu {
            Picker("Show", selection: $filter.scope) {
                Label("All items", systemImage: "tray.full").tag(ListFilter.Scope.all)
                Label("Favorites", systemImage: "star").tag(ListFilter.Scope.favorites)
                Label("Trash", systemImage: "trash").tag(ListFilter.Scope.trash)
            }
            .pickerStyle(.inline)
            Picker(selection: $filter.kind) {
                Text("All types").tag(ItemKind?.none)
                ForEach(ItemKind.allCases) { Label($0.label, systemImage: $0.symbol).tag(ItemKind?.some($0)) }
            } label: {
                Label("Type", systemImage: "square.grid.2x2")
            }
            .pickerStyle(.menu)
            Picker(selection: $filter.folder) {
                Text("All folders").tag(String?.none)
                Text("No folder").tag(String?.some(""))
                ForEach(folders, id: \.self) { Text($0).tag(String?.some($0)) }
            } label: {
                Label("Folder", systemImage: "folder")
            }
            .pickerStyle(.menu)
            if (v?.vaults.count ?? 0) > 1 {
                Picker(selection: $filter.vaultId) {
                    Text("All vaults").tag(String?.none)
                    ForEach(v?.vaults ?? []) { Text($0.name).tag(String?.some($0.id)) }
                } label: {
                    Label("Vault", systemImage: "lock.rectangle.stack")
                }
                .pickerStyle(.menu)
            }
            if filter.active {
                Divider()
                Button("Clear filters", role: .destructive) { filter = ListFilter() }
            }
        } label: {
            Image(systemName: filter.active ? "line.3.horizontal.decrease.circle.fill" : "line.3.horizontal.decrease.circle")
        }
        .accessibilityLabel("Filters")
        .accessibilityIdentifier("filters")
    }
}

/// Account menu: who is signed in, other accounts to switch to, add account, lock, web vault, log out.
struct AccountMenu: View {
    @Environment(AppModel.self) private var model
    @State private var confirmLogout = false

    var body: some View {
        let s = model.state
        Menu {
            Section(s.name.isEmpty ? s.email : "\(s.name) · \(s.email)") {
                Text(hostOf(s.server))
            }
            ForEach(s.accounts.filter { $0.id != s.activeId }) { a in
                Button {
                    model.run { try await model.repo.switchAccount(a.id) }
                } label: {
                    Label {
                        Text(a.name.isEmpty ? a.email : a.name)
                        Text("\(hostOf(a.server)) · \(statusLabel(a.status))")
                    } icon: {
                        Image(systemName: "person.crop.circle")
                    }
                }
            }
            if s.accounts.count < maxAccounts {
                Button { model.run { try await model.repo.addAccount() } } label: { Label("Add account", systemImage: "person.badge.plus") }
            }
            Divider()
            Button { model.run { await model.repo.lockActive() } } label: { Label("Lock", systemImage: "lock") }
            Button { model.openWebVault() } label: { Label("Open web vault", systemImage: "safari") }
            Button(role: .destructive) { confirmLogout = true } label: { Label("Log out…", systemImage: "rectangle.portrait.and.arrow.right") }
        } label: {
            Avatar(text: initials(s.name, s.email), size: 30)
        }
        .accessibilityLabel("Account menu: \(s.name.isEmpty ? s.email : s.name)")
        .accessibilityIdentifier("accountMenu")
        .confirmationDialog("Log out?", isPresented: $confirmLogout, titleVisibility: .visible) {
            Button("Log out", role: .destructive) { model.run { await model.repo.logout() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(LogoutCopy.message(email: s.email, others: s.accounts.count > 1))
        }
    }
}
