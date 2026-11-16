import PassAuthCore
import PassAuthKit
import SwiftUI
import UIKit

// Settings → Password health and the password notes on an item's page, as in the web vault
// (`pages/Health.tsx`, `lib/health-session.ts`); the rules are in Shared/PasswordHealth.swift.

/// Password health for the unlocked vault in this app session. The report is worked out again only
/// when the vault changes. The breach check runs only when the user asks and the server allows it
/// (feature `breach_check`), on its own ephemeral session. The report, the check's results and the
/// kept range answers stay in memory and are dropped when the vault locks, signs out or the
/// account changes (`VaultRepository.onVaultClosed`).
@MainActor
@Observable
final class HealthSession {
    enum Status: Equatable { case idle, checking, done, failed }
    /// `unknown`: the server's settings couldn't be loaded.
    enum Availability: Equatable { case loading, on, off, unknown }

    private(set) var status = Status.idle
    /// While checking: distinct passwords checked so far, of `total`.
    private(set) var done = 0
    private(set) var total = 0
    /// Times seen per password, from the last finished check; passwords added or changed since are missing.
    private(set) var results: BreachResults?
    /// When `results` came in.
    private(set) var checkedAt: Date?
    /// Why the last check stopped, in plain words.
    private(set) var error: String?
    private(set) var availability = Availability.loading

    @ObservationIgnored private let repo: VaultRepository
    @ObservationIgnored private let checker: BreachChecker
    /// Bumped when the vault closes: a check or a settings request started before that is dropped.
    @ObservationIgnored private var generation = 0
    @ObservationIgnored private var memo: (key: Int, report: HealthReport)?

    init(repo: VaultRepository, checker: BreachChecker = BreachChecker()) {
        self.repo = repo
        self.checker = checker
        repo.onVaultClosed = { [weak self] in self?.clear() }
    }

    /// Weak and reused passwords in `v` (every vault the user can read); an unchanged vault gives
    /// back the same report.
    func report(_ v: VaultData) -> HealthReport {
        var h = Hasher()
        h.combine(v.entries.count)
        for e in v.entries {
            h.combine(e.id)
            h.combine(e.revision)
            h.combine(e.deletedAt)
            h.combine(e.item.login?.password)
        }
        let key = h.finalize()
        if let memo, memo.key == key { return memo.report }
        let report = HealthReport(entries: v.entries) { estimateBits(password: $0) }
        memo = (key, report)
        return report
    }

    /// Whether the server allows the breach check (asked each time the page opens).
    func loadAvailability() async {
        let gen = generation
        if availability == .unknown { availability = .loading }
        let features = await repo.serverFeatures()
        guard gen == generation else { return }
        availability = features.map { $0.contains(breachCheckFeature) ? .on : .off } ?? .unknown
    }

    /// Check the password of every login the user can read against Have I Been Pwned, if the
    /// server allows it. A previous check's results stay until this one finishes.
    func check() {
        guard status != .checking, repo.vault != nil else { return }
        let gen = generation
        status = .checking
        done = 0
        total = 0
        error = nil
        Task {
            let features = await repo.serverFeatures()
            guard gen == generation else { return }
            guard let features else { return fail(HealthText.noConfig, gen) }
            guard features.contains(breachCheckFeature) else {
                // Switched off since the page opened: the page now says so instead of the button.
                availability = .off
                status = .idle
                return
            }
            availability = .on
            guard let v = repo.vault else { return fail(HealthText.stopped, gen) }
            let passwords = report(v).logins.map { $0.item.login?.password ?? "" }
            do {
                let found = try await checker.check(passwords) { done, total in
                    guard gen == self.generation else { return }
                    self.done = done
                    self.total = total
                }
                guard gen == generation else { return }
                results = found
                checkedAt = Date()
                status = .done
            } catch {
                fail(HealthText.explain(error), gen)
            }
        }
    }

    private func fail(_ message: String, _ gen: Int) {
        guard gen == generation else { return }
        status = .failed
        error = message
    }

    #if DEBUG
    /// UI tests (`-PAStubBreachCheck`): "sunshine1" was seen 42 times, "qwerty" 3,946,737 times,
    /// nothing else; padded answers after a short wait, without asking Have I Been Pwned.
    nonisolated static let stubFetch: BreachChecker.Fetch = { request in
        let prefix = request.url?.lastPathComponent ?? ""
        var lines = (0..<3).map { "\(String(repeating: "F", count: 34))\($0):0" }
        for (password, count) in [("sunshine1", 42), ("qwerty", 3_946_737)] {
            let hash = PwnedPasswords.sha1Hex(password)
            if hash.hasPrefix(prefix) { lines.append("\(hash.dropFirst(5)):\(count)") }
        }
        try await Task.sleep(for: .milliseconds(400))
        return RangeAnswer(status: 200, body: Data(lines.joined(separator: "\r\n").utf8))
    }
    #endif

    /// The vault closed: stop a running check and forget the report, results and kept answers.
    func clear() {
        generation += 1
        checker.clear()
        memo = nil
        status = .idle
        done = 0
        total = 0
        results = nil
        checkedAt = nil
        error = nil
        availability = .loading
    }
}

/// Names compared as the web vault does (`localeCompare`, base sensitivity), "Untitled" for none.
private func byName(_ a: Entry, _ b: Entry) -> Bool {
    let x = a.item.name.isEmpty ? "Untitled" : a.item.name
    let y = b.item.name.isEmpty ? "Untitled" : b.item.name
    return x.compare(y, options: [.caseInsensitive, .diacriticInsensitive], locale: .current) == .orderedAscending
}

/// Weak, reused and exposed passwords across every vault the user can read. Rows open the login:
/// in its editor when the user can change it, else its page.
struct HealthView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dynamicTypeSize) private var typeSize
    @State private var editing: EditTarget?
    @AccessibilityFocusState private var exposedHeadingFocused: Bool

    var body: some View {
        Group {
            if let v = model.repo.vault {
                content(v, model.health.report(v))
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Password health")
        .navigationBarTitleDisplayMode(.inline)
        .paNavBar()
        .task { await model.health.loadAvailability() }
        .sheet(item: $editing) { target in
            EditSheet(target: target) { _ in }
        }
    }

    @ViewBuilder
    private func content(_ v: VaultData, _ report: HealthReport) -> some View {
        let health = model.health
        let results = health.results
        let password = { (e: Entry) in e.item.login?.password ?? "" }
        let seen = { (e: Entry) in results?.timesSeen(password(e)) ?? 0 }
        let exposed = results == nil ? [] : report.logins.filter { seen($0) > 0 }.sorted { seen($0) != seen($1) ? seen($0) > seen($1) : byName($0, $1) }
        let unchecked = results.map { r in report.logins.filter { r.timesSeen(password($0)) == nil }.count } ?? 0
        let reusedLogins = report.reused.reduce(0) { $0 + $1.count }
        List {
            Section {
                Text("Find the logins to fix first: passwords exposed in a data breach, used for more than one login, or easy to guess. Weak and reused passwords are found in this app, without sending anything.")
                    .font(.subheadline)
                    .foregroundStyle(Color.paMuted)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 4, leading: 4, bottom: 4, trailing: 4))
            }
            if report.logins.isEmpty {
                ContentUnavailableView {
                    Label("No passwords to check yet", systemImage: "checkmark.shield")
                } description: {
                    Text("When your logins have passwords, this page shows which ones are weak, reused or exposed in a data breach.")
                } actions: {
                    Button("Add a login") { editing = .new(.login) }.buttonStyle(.borderedProminent)
                    Button("Import from another app") { model.openWebVault("/import") }
                }
                .listRowBackground(Color.clear)
            } else {
                summary(report, exposed: exposed.count, reusedLogins: reusedLogins)
                exposedSection(v, exposed: exposed, unchecked: unchecked, total: report.logins.count, seen: seen)
                reusedSection(v, report, reusedLogins: reusedLogins)
                weakSection(v, report)
            }
        }
        .listStyle(.insetGrouped)
        .paList()
        // VoiceOver hears the progress in steps of a quarter, then the outcome.
        .onChange(of: health.status == .checking ? HealthText.progress(done: health.done, total: health.total) : "") { _, text in
            if !text.isEmpty { UIAccessibility.post(notification: .announcement, argument: text) }
        }
        .onChange(of: health.status) { old, now in
            switch now {
            case .done: UIAccessibility.post(notification: .announcement, argument: HealthText.finished(exposed: exposed.count))
            case .failed: UIAccessibility.post(notification: .announcement, argument: health.error ?? HealthText.stopped)
            default: break
            }
            // The button that started the check is gone or changed: keep VoiceOver on the section.
            if old == .checking && now != .checking { exposedHeadingFocused = true }
        }
    }

    // MARK: Summary

    private func summary(_ report: HealthReport, exposed: Int, reusedLogins: Int) -> some View {
        let health = model.health
        let columns = Array(repeating: GridItem(.flexible(), spacing: PA.Space.s, alignment: .top), count: typeSize.isAccessibilitySize ? 1 : 2)
        return Section {
            LazyVGrid(columns: columns, alignment: .leading, spacing: PA.Space.s) {
                if health.results != nil {
                    Stat(value: exposed.formatted(), label: "Exposed", tone: exposed > 0 ? .bad : nil)
                } else if health.availability != .off && health.availability != .unknown {
                    Stat(value: "–", label: "Exposed: not checked yet", tone: nil)
                }
                Stat(value: reusedLogins.formatted(), label: "Reused", tone: reusedLogins > 0 ? .warn : nil)
                Stat(value: report.weak.count.formatted(), label: "Weak", tone: report.weak.isEmpty ? nil : .warn)
                Stat(value: report.logins.count.formatted(), label: report.logins.count == 1 ? "Login with a password" : "Logins with a password", tone: nil)
            }
            .padding(.vertical, PA.Space.xs)
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Summary")
        }
        .paRow()
    }

    // MARK: Exposed

    @ViewBuilder
    private func exposedSection(_ v: VaultData, exposed: [Entry], unchecked: Int, total: Int, seen: @escaping (Entry) -> Int) -> some View {
        let health = model.health
        let checking = health.status == .checking
        let allowed = health.availability == .on
        Section {
            Text("Attackers try passwords from known breaches first, on every site. Change these even if they look strong.")
                .font(.subheadline).foregroundStyle(Color.paInk)
                .paRow()
            switch health.availability {
            case .off, .unknown:
                Text(health.availability == .off ? HealthText.notAllowed : HealthText.unavailable)
                    .font(.footnote).foregroundStyle(Color.paMuted)
                    .paRow()
                if health.availability == .unknown {
                    Button("Try again") { Task { await health.loadAvailability() } }.paRow()
                }
            case .loading, .on:
                Label {
                    Text(HealthText.privacy).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "checkmark.shield").foregroundStyle(Color.paOk)
                }
                .font(.footnote).foregroundStyle(Color.paMuted)
                .paRow()
            }
            if allowed && health.results == nil {
                Button { health.check() } label: {
                    Label(checking ? "Checking…" : health.status == .failed ? "Try again" : "Check for exposed passwords", systemImage: "checkmark.shield")
                        .fontWeight(.semibold)
                }
                .disabled(checking)
                .accessibilityIdentifier("health.check")
                .paRow()
            }
            if checking {
                VStack(alignment: .leading, spacing: 6) {
                    ProgressView(value: Double(health.done), total: Double(max(health.total, 1)))
                        .accessibilityLabel("Breach check")
                    Text(health.total > 0 ? "Checked \(health.done.formatted()) of \(HealthText.count(health.total, "password", "passwords"))" : "Starting…")
                        .font(.footnote).foregroundStyle(Color.paMuted)
                        .accessibilityHidden(true)
                }
                .padding(.vertical, 4)
                .paRow()
            }
            if health.status == .failed, let error = health.error {
                Notice(text: error, kind: .error)
                    .listRowInsets(EdgeInsets(top: 6, leading: 8, bottom: 6, trailing: 8))
                    .paRow()
            }
            if health.results != nil {
                if !exposed.isEmpty {
                    ForEach(exposed) { e in row(v, e, trail: HealthText.timesSeen(seen(e))) }
                } else if unchecked < total {
                    AllClear(title: "No exposed passwords found", text: "None of the checked passwords appear in known data breaches.").paRow()
                }
                if allowed {
                    Button(checking ? "Checking…" : "Check again") { health.check() }
                        .disabled(checking)
                        .accessibilityIdentifier("health.checkAgain")
                        .paRow()
                }
                let when = health.checkedAt.map { "Last checked at \($0.formatted(date: .omitted, time: .shortened)). " } ?? ""
                let changed = unchecked > 0 ? "\(HealthText.count(unchecked, "login was", "logins were")) added or changed since then; check again to include them." : ""
                if !(when + changed).isEmpty {
                    Text(when + changed).font(.footnote).foregroundStyle(Color.paMuted).paRow()
                }
            }
        } header: {
            header("Exposed in data breaches", badge: health.results.map { _ in exposed.isEmpty ? "None found" : exposed.count.formatted() }, tone: exposed.isEmpty ? .ok : .warn)
                .accessibilityFocused($exposedHeadingFocused)
        }
    }

    // MARK: Reused and weak

    @ViewBuilder
    private func reusedSection(_ v: VaultData, _ report: HealthReport, reusedLogins: Int) -> some View {
        Section {
            Text("When one site leaks a password that other logins use too, all of them are at risk. Give each login its own password.")
                .font(.subheadline).foregroundStyle(Color.paInk)
                .paRow()
            if report.reused.isEmpty {
                AllClear(title: "No reused passwords", text: "Every login has its own password.").paRow()
            }
        } header: {
            header("Reused passwords", badge: reusedLogins > 0 ? reusedLogins.formatted() : nil, tone: nil)
        }
        ForEach(report.reused.map { (id: $0[0].id, group: $0) }, id: \.id) { _, group in
            Section {
                ForEach(group.sorted(by: byName)) { e in row(v, e) }
            } header: {
                Text("Same password in \(HealthText.count(group.count, "login", "logins"))")
                    .textCase(nil)
                    .accessibilityAddTraits(.isHeader)
            }
        }
    }

    private func weakSection(_ v: VaultData, _ report: HealthReport) -> some View {
        Section {
            Text("These passwords are short or use few kinds of characters, so they're easy to guess. Replace them with generated ones.")
                .font(.subheadline).foregroundStyle(Color.paInk)
                .paRow()
            if report.weak.isEmpty {
                AllClear(title: "No weak passwords", text: "Every password is long and varied enough.").paRow()
            } else {
                ForEach(report.weak.sorted(by: byName)) { e in row(v, e) }
            }
        } header: {
            header("Weak passwords", badge: report.weak.isEmpty ? nil : report.weak.count.formatted(), tone: nil)
        }
    }

    // MARK: Parts

    private func header(_ title: String, badge: String?, tone: Stat.Tone?) -> some View {
        let color = tone?.color ?? Color.paMuted
        return HStack(spacing: 8) {
            Text(title).accessibilityAddTraits(.isHeader)
            if let badge {
                Text(badge)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(color)
                    .padding(.horizontal, 7).padding(.vertical, 2)
                    .background(color.opacity(0.14), in: Capsule())
                    .accessibilityLabel(badge == "None found" ? "none found" : "\(badge) logins")
            }
        }
        .textCase(nil)
    }

    /// One login: opens its editor when the user can change it (the sheet comes back here after
    /// saving), else its page.
    @ViewBuilder
    private func row(_ v: VaultData, _ e: Entry, trail: String? = nil) -> some View {
        let vault = v.vaults.first { $0.id == e.vaultId }
        let canEdit = vault.map { $0.role != .read } ?? false
        if canEdit {
            Button { editing = .edit(e.id) } label: {
                HStack {
                    HealthRow(entry: e, vault: vault, canEdit: true, trail: trail)
                    Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(Color.paMuted).accessibilityHidden(true)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityHint("Opens the editor to change the password.")
            .accessibilityIdentifier("health.row:\(e.item.name)")
            .paRow()
        } else {
            NavigationLink {
                ItemView(id: e.id) { editing = .edit(e.id) }
            } label: {
                HealthRow(entry: e, vault: vault, canEdit: false, trail: trail)
            }
            .accessibilityIdentifier("health.row:\(e.item.name)")
            .paRow()
        }
    }
}

/// A login on the health page: name, user name and site, its vault (shared vaults marked).
private struct HealthRow: View {
    @Environment(\.dynamicTypeSize) private var typeSize
    let entry: Entry
    let vault: VaultInfo?
    let canEdit: Bool
    let trail: String?

    var body: some View {
        let i = entry.item
        let host = i.siteHost
        let shared = vault.map { !$0.personal } ?? false
        let details = [i.login?.username ?? "", host].filter { !$0.isEmpty }.joined(separator: " · ")
        let place = (vault?.name ?? "Vault") + (shared ? " (shared)" : "") + (canEdit ? "" : ", view only")
        let lines: Int? = typeSize.isAccessibilitySize ? nil : 1
        let big = typeSize.isAccessibilitySize
        let layout = big ? AnyLayout(VStackLayout(alignment: .leading, spacing: 6)) : AnyLayout(HStackLayout(spacing: PA.Space.m))
        layout {
            SiteIcon(host: host, name: i.name, kind: .login)
            VStack(alignment: .leading, spacing: 2) {
                Text(i.name.isEmpty ? "Untitled" : i.name).foregroundStyle(Color.paInk).lineLimit(lines)
                if !details.isEmpty { Text(details).font(.subheadline).foregroundStyle(Color.paMuted).lineLimit(lines) }
                HStack(spacing: 4) {
                    if shared { Image(systemName: "person.2").accessibilityHidden(true) }
                    Text(place).lineLimit(lines)
                }
                .font(.caption).foregroundStyle(Color.paMuted)
                // Under the name (a narrow screen has no room for a column of its own).
                if let trail {
                    Text(trail).font(.footnote.weight(.medium)).foregroundStyle(Color.paDanger)
                }
            }
            if !big { Spacer(minLength: 0) }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

/// A summary number.
private struct Stat: View {
    enum Tone {
        case ok, warn, bad
        var color: Color {
            switch self {
            case .ok: Color.paOk
            case .warn: Color.paWarn
            case .bad: Color.paDanger
            }
        }
    }

    let value: String
    let label: String
    let tone: Tone?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value).font(.title2.weight(.semibold)).monospacedDigit().foregroundStyle(tone?.color ?? Color.paInk)
            Text(label).font(.caption).foregroundStyle(Color.paMuted).fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, PA.Space.m)
        .padding(.vertical, PA.Space.s)
        .background(Color.paSurface2, in: RoundedRectangle(cornerRadius: PA.Radius.control, style: .continuous))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(value == "–" ? label : "\(label): \(value)")
    }
}

/// Nothing to fix in a section.
private struct AllClear: View {
    let title: String
    let text: String

    var body: some View {
        HStack(spacing: PA.Space.m) {
            Image(systemName: "checkmark.circle.fill").font(.title3).foregroundStyle(Color.paOk).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).foregroundStyle(Color.paInk)
                Text(text).font(.subheadline).foregroundStyle(Color.paMuted)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

private struct Note: Identifiable {
    let text: String
    let color: Color
    var id: String { text }
}

/// Quiet notes about a login's password on its page: weak, used by other logins, found in a data
/// breach (only after a breach check in this app session found it). Same rules as Password health.
struct PasswordNotes: View {
    @Environment(AppModel.self) private var model
    let entry: Entry
    /// "Change password" (opens the editor) when the user can change the login.
    let onChange: (() -> Void)?

    var body: some View {
        let notes = self.notes()
        if !notes.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(notes) { note in
                        Label {
                            Text(note.text).fixedSize(horizontal: false, vertical: true)
                        } icon: {
                            Image(systemName: "exclamationmark.shield")
                        }
                        .foregroundStyle(note.color)
                    }
                }
                .font(.footnote)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Password health: " + notes.map(\.text).joined(separator: ", "))
                .accessibilityIdentifier("passwordNotes")
                if let onChange {
                    Button("Change password", action: onChange)
                        .font(.footnote.weight(.medium))
                        .buttonStyle(.borderless)
                }
            }
            .padding(.vertical, 2)
            .paRow()
        }
    }

    private func notes() -> [Note] {
        let password = entry.item.login?.password ?? ""
        guard !password.isEmpty, entry.deletedAt == nil, let v = model.repo.vault else { return [] }
        var notes: [Note] = []
        if PasswordHealth.isWeak(password, bits: { estimateBits(password: $0) }) { notes.append(Note(text: "Weak password", color: .paWarn)) }
        let others = model.health.report(v).reuseCount[entry.id] ?? 0
        if others > 0 { notes.append(Note(text: HealthText.usedIn(others), color: .paWarn)) }
        if (model.health.results?.timesSeen(password) ?? 0) > 0 { notes.append(Note(text: "Found in a data breach", color: .paDanger)) }
        return notes
    }
}
