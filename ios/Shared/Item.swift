import Foundation

/// The decrypted item, in exactly the JSON shape of `passauth_core::item` and the web
/// vault's `web/src/lib/types.ts` (snake_case). Items cross into the Rust core as this
/// JSON; the core stamps `format` and upgrades older items. Decoding is lenient (missing
/// keys take defaults, unknown values fall back), encoding writes every key (nulls
/// included) except an unknown `format`, which the core rejects as null.
public struct Item: Codable, Equatable, Sendable {
    public var format: Int?
    public var name: String = ""
    public var notes: String = ""
    public var favorite: Bool = false
    public var folder: String?
    public var tags: [String] = []
    public var login: Login?
    public var card: Card?
    public var identity: Identity?
    public var sshKey: SshKey?
    public var fields: [Field] = []
    public var passwordHistory: [PasswordChange] = []
    public var createdAt: Int64 = 0
    public var updatedAt: Int64 = 0
    /// The item's files (`attachments: [{id, name, size, key}]`, servers with the `attachments`
    /// feature), as written: entries are kept whole, so fields a newer app adds to one survive an
    /// edit here; nil when the item has none (the field is then left out). Read through
    /// `AttachmentList.read`.
    public var attachments: [JSON]?
    /// The item's edit counter (inside the ciphertext, so authenticated): the core writes
    /// `rev + 1` on every encryption; 0 = never counted (left out when written). Read only for
    /// the app: rollback detection (`ItemRevMemory`) compares it, editors never change it.
    public var rev: UInt64 = 0
    /// Top-level fields this app doesn't know (a newer app's), written back unchanged.
    public var extra: [String: JSON] = [:]

    public init(name: String = "", notes: String = "", favorite: Bool = false, folder: String? = nil, login: Login? = nil, card: Card? = nil, identity: Identity? = nil, sshKey: SshKey? = nil, fields: [Field] = [], createdAt: Int64 = 0, updatedAt: Int64 = 0) {
        self.name = name
        self.notes = notes
        self.favorite = favorite
        self.folder = folder
        self.login = login
        self.card = card
        self.identity = identity
        self.sshKey = sshKey
        self.fields = fields
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    enum CodingKeys: String, CodingKey, CaseIterable {
        case format, name, notes, favorite, folder, tags, login, card, identity, fields, attachments, rev
        case sshKey = "ssh_key", passwordHistory = "password_history", createdAt = "created_at", updatedAt = "updated_at"
    }

    private static let knownKeys = Set(CodingKeys.allCases.map(\.rawValue))

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        format = c.lenient(.format, nil as Int?)
        name = c.lenient(.name, "")
        notes = c.lenient(.notes, "")
        favorite = c.lenient(.favorite, false)
        folder = c.lenient(.folder, nil as String?)
        tags = c.lenient(.tags, [])
        login = c.lenient(.login, nil as Login?)
        card = c.lenient(.card, nil as Card?)
        identity = c.lenient(.identity, nil as Identity?)
        sshKey = c.lenient(.sshKey, nil as SshKey?)
        fields = c.lenient(.fields, [])
        passwordHistory = c.lenient(.passwordHistory, [])
        createdAt = c.lenient(.createdAt, 0)
        updatedAt = c.lenient(.updatedAt, 0)
        attachments = c.lenient(.attachments, nil as [JSON]?)
        rev = c.lenient(.rev, 0 as UInt64)
        extra = decoder.unknownFields(Self.knownKeys)
        // An `attachments` value that isn't a list (a newer app's shape) is kept as written.
        if attachments == nil, let raw = c.lenient(.attachments, nil as JSON?), raw != .null { extra[CodingKeys.attachments.rawValue] = raw }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(format, forKey: .format)
        try c.encode(name, forKey: .name)
        try c.encode(notes, forKey: .notes)
        try c.encode(favorite, forKey: .favorite)
        try c.encode(folder, forKey: .folder)
        try c.encode(tags, forKey: .tags)
        try c.encode(login, forKey: .login)
        try c.encode(card, forKey: .card)
        try c.encode(identity, forKey: .identity)
        try c.encode(sshKey, forKey: .sshKey)
        try c.encode(fields, forKey: .fields)
        try c.encode(passwordHistory, forKey: .passwordHistory)
        try c.encode(createdAt, forKey: .createdAt)
        try c.encode(updatedAt, forKey: .updatedAt)
        try c.encodeIfPresent(attachments, forKey: .attachments)
        if rev > 0 { try c.encode(rev, forKey: .rev) }
        try encoder.encodeUnknown(extra, known: Self.knownKeys)
        if attachments == nil, let raw = extra[CodingKeys.attachments.rawValue] { try c.encode(raw, forKey: .attachments) }
    }

    public var kind: ItemKind {
        if login != nil { return .login }
        if card != nil { return .card }
        if identity != nil { return .identity }
        if sshKey != nil { return .sshKey }
        return .note
    }

    /// Host of the first website (patterns excluded), for site icons.
    public var siteHost: String {
        for u in login?.urls ?? [] {
            if u.match == .regex || u.url.trimmingCharacters(in: .whitespaces).isEmpty { continue }
            guard let p = UrlMatcher.parse(u.url) else { continue }
            if p.scheme == "http" || p.scheme == "https" { return p.hostname }
        }
        return ""
    }

    public static func empty(_ kind: ItemKind, now: Int64 = Int64(Date().timeIntervalSince1970)) -> Item {
        Item(
            login: kind == .login ? Login(urls: [LoginUrl()]) : nil,
            card: kind == .card ? Card() : nil,
            identity: kind == .identity ? Identity() : nil,
            sshKey: kind == .sshKey ? SshKey() : nil,
            createdAt: now,
            updatedAt: now
        )
    }
}

public enum ItemKind: String, CaseIterable, Sendable, Identifiable {
    case login, note, card, identity, sshKey

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .login: "Login"
        case .note: "Secure note"
        case .card: "Card"
        case .identity: "Identity"
        case .sshKey: "SSH key"
        }
    }

    /// SF Symbol for the kind.
    public var symbol: String {
        switch self {
        case .login: "globe"
        case .note: "note.text"
        case .card: "creditcard"
        case .identity: "person.text.rectangle"
        case .sshKey: "terminal"
        }
    }
}

public enum UrlMatch: String, Codable, CaseIterable, Sendable {
    case `default` = "default", domain, host, startsWith = "starts_with", exact, regex, never

    public init(from decoder: Decoder) throws {
        let s = (try? decoder.singleValueContainer().decode(String.self)) ?? ""
        self = UrlMatch(rawValue: s) ?? .default
    }
}

public struct LoginUrl: Codable, Equatable, Sendable {
    public var url: String = ""
    public var match: UrlMatch = .default
    /// Fields this app doesn't know (a newer app's), written back unchanged.
    public var extra: [String: JSON] = [:]

    enum CodingKeys: String, CodingKey, CaseIterable { case url, match }
    private static let knownKeys = Set(CodingKeys.allCases.map(\.rawValue))

    public init(url: String = "", match: UrlMatch = .default) {
        self.url = url
        self.match = match
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        url = c.lenient(.url, "")
        match = c.lenient(.match, .default)
        extra = decoder.unknownFields(Self.knownKeys)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(url, forKey: .url)
        try c.encode(match, forKey: .match)
        try encoder.encodeUnknown(extra, known: Self.knownKeys)
    }
}

public struct Passkey: Codable, Equatable, Sendable {
    public var credentialId = ""
    public var rpId = ""
    public var rpName = ""
    public var userHandle = ""
    public var userName = ""
    public var userDisplayName = ""
    public var algorithm: Int = -7
    public var privateKey = ""
    public var counter: Int64 = 0
    public var discoverable = true
    public var createdAt: Int64 = 0
    /// Fields this app doesn't know (a newer app's), written back unchanged.
    public var extra: [String: JSON] = [:]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case credentialId = "credential_id", rpId = "rp_id", rpName = "rp_name", userHandle = "user_handle"
        case userName = "user_name", userDisplayName = "user_display_name", algorithm, privateKey = "private_key"
        case counter, discoverable, createdAt = "created_at"
    }
    private static let knownKeys = Set(CodingKeys.allCases.map(\.rawValue))

    public init() {}

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        credentialId = c.lenient(.credentialId, "")
        rpId = c.lenient(.rpId, "")
        rpName = c.lenient(.rpName, "")
        userHandle = c.lenient(.userHandle, "")
        userName = c.lenient(.userName, "")
        userDisplayName = c.lenient(.userDisplayName, "")
        algorithm = c.lenient(.algorithm, -7)
        privateKey = c.lenient(.privateKey, "")
        counter = c.lenient(.counter, 0)
        discoverable = c.lenient(.discoverable, true)
        createdAt = c.lenient(.createdAt, 0)
        extra = decoder.unknownFields(Self.knownKeys)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(credentialId, forKey: .credentialId)
        try c.encode(rpId, forKey: .rpId)
        try c.encode(rpName, forKey: .rpName)
        try c.encode(userHandle, forKey: .userHandle)
        try c.encode(userName, forKey: .userName)
        try c.encode(userDisplayName, forKey: .userDisplayName)
        try c.encode(algorithm, forKey: .algorithm)
        try c.encode(privateKey, forKey: .privateKey)
        try c.encode(counter, forKey: .counter)
        try c.encode(discoverable, forKey: .discoverable)
        try c.encode(createdAt, forKey: .createdAt)
        try encoder.encodeUnknown(extra, known: Self.knownKeys)
    }
}

public struct Login: Codable, Equatable, Sendable {
    public var username = ""
    public var password = ""
    public var urls: [LoginUrl] = []
    public var totp: String?
    public var passkeys: [Passkey] = []
    /// Fields this app doesn't know (a newer app's), written back unchanged.
    public var extra: [String: JSON] = [:]

    enum CodingKeys: String, CodingKey, CaseIterable { case username, password, urls, totp, passkeys }
    private static let knownKeys = Set(CodingKeys.allCases.map(\.rawValue))

    public init(username: String = "", password: String = "", urls: [LoginUrl] = [], totp: String? = nil) {
        self.username = username
        self.password = password
        self.urls = urls
        self.totp = totp
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        username = c.lenient(.username, "")
        password = c.lenient(.password, "")
        urls = c.lenient(.urls, [])
        totp = c.lenient(.totp, nil as String?)
        passkeys = c.lenient(.passkeys, [])
        extra = decoder.unknownFields(Self.knownKeys)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(username, forKey: .username)
        try c.encode(password, forKey: .password)
        try c.encode(urls, forKey: .urls)
        try c.encode(totp, forKey: .totp)
        try c.encode(passkeys, forKey: .passkeys)
        try encoder.encodeUnknown(extra, known: Self.knownKeys)
    }
}

public struct Card: Codable, Equatable, Sendable {
    public var cardholderName = ""
    public var brand = ""
    public var number = ""
    public var expMonth = ""
    public var expYear = ""
    public var code = ""
    /// Fields this app doesn't know (a newer app's), written back unchanged.
    public var extra: [String: JSON] = [:]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case cardholderName = "cardholder_name", brand, number, expMonth = "exp_month", expYear = "exp_year", code
    }
    private static let knownKeys = Set(CodingKeys.allCases.map(\.rawValue))

    public init() {}

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        cardholderName = c.lenient(.cardholderName, "")
        brand = c.lenient(.brand, "")
        number = c.lenient(.number, "")
        expMonth = c.lenient(.expMonth, "")
        expYear = c.lenient(.expYear, "")
        code = c.lenient(.code, "")
        extra = decoder.unknownFields(Self.knownKeys)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(cardholderName, forKey: .cardholderName)
        try c.encode(brand, forKey: .brand)
        try c.encode(number, forKey: .number)
        try c.encode(expMonth, forKey: .expMonth)
        try c.encode(expYear, forKey: .expYear)
        try c.encode(code, forKey: .code)
        try encoder.encodeUnknown(extra, known: Self.knownKeys)
    }
}

public struct Identity: Codable, Equatable, Sendable {
    public var title = ""
    public var firstName = ""
    public var middleName = ""
    public var lastName = ""
    public var company = ""
    public var email = ""
    public var phone = ""
    public var address1 = ""
    public var address2 = ""
    public var city = ""
    public var state = ""
    public var postalCode = ""
    public var country = ""
    public var username = ""
    public var ssn = ""
    public var passportNumber = ""
    public var licenseNumber = ""
    /// Fields this app doesn't know (a newer app's), written back unchanged.
    public var extra: [String: JSON] = [:]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case title, firstName = "first_name", middleName = "middle_name", lastName = "last_name", company, email, phone
        case address1, address2, city, state, postalCode = "postal_code", country, username, ssn
        case passportNumber = "passport_number", licenseNumber = "license_number"
    }
    private static let knownKeys = Set(CodingKeys.allCases.map(\.rawValue))

    public init() {}

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        title = c.lenient(.title, "")
        firstName = c.lenient(.firstName, "")
        middleName = c.lenient(.middleName, "")
        lastName = c.lenient(.lastName, "")
        company = c.lenient(.company, "")
        email = c.lenient(.email, "")
        phone = c.lenient(.phone, "")
        address1 = c.lenient(.address1, "")
        address2 = c.lenient(.address2, "")
        city = c.lenient(.city, "")
        state = c.lenient(.state, "")
        postalCode = c.lenient(.postalCode, "")
        country = c.lenient(.country, "")
        username = c.lenient(.username, "")
        ssn = c.lenient(.ssn, "")
        passportNumber = c.lenient(.passportNumber, "")
        licenseNumber = c.lenient(.licenseNumber, "")
        extra = decoder.unknownFields(Self.knownKeys)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        for (key, value) in [(CodingKeys.title, title), (.firstName, firstName), (.middleName, middleName), (.lastName, lastName),
                             (.company, company), (.email, email), (.phone, phone), (.address1, address1), (.address2, address2),
                             (.city, city), (.state, state), (.postalCode, postalCode), (.country, country), (.username, username),
                             (.ssn, ssn), (.passportNumber, passportNumber), (.licenseNumber, licenseNumber)] {
            try c.encode(value, forKey: key)
        }
        try encoder.encodeUnknown(extra, known: Self.knownKeys)
    }
}

public struct SshKey: Codable, Equatable, Sendable {
    public var privateKey = ""
    public var publicKey = ""
    public var fingerprint = ""
    /// Fields this app doesn't know (a newer app's), written back unchanged.
    public var extra: [String: JSON] = [:]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case privateKey = "private_key", publicKey = "public_key", fingerprint
    }
    private static let knownKeys = Set(CodingKeys.allCases.map(\.rawValue))

    public init() {}

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        privateKey = c.lenient(.privateKey, "")
        publicKey = c.lenient(.publicKey, "")
        fingerprint = c.lenient(.fingerprint, "")
        extra = decoder.unknownFields(Self.knownKeys)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(privateKey, forKey: .privateKey)
        try c.encode(publicKey, forKey: .publicKey)
        try c.encode(fingerprint, forKey: .fingerprint)
        try encoder.encodeUnknown(extra, known: Self.knownKeys)
    }
}

public enum FieldType: String, Codable, CaseIterable, Sendable {
    case text, hidden, boolean

    public init(from decoder: Decoder) throws {
        let s = (try? decoder.singleValueContainer().decode(String.self)) ?? ""
        self = FieldType(rawValue: s) ?? .text
    }
}

public struct Field: Codable, Equatable, Sendable {
    public var name = ""
    public var value = ""
    public var type: FieldType = .text
    /// Fields this app doesn't know (a newer app's), written back unchanged.
    public var extra: [String: JSON] = [:]

    enum CodingKeys: String, CodingKey, CaseIterable { case name, value, type }
    private static let knownKeys = Set(CodingKeys.allCases.map(\.rawValue))

    public init(name: String = "", value: String = "", type: FieldType = .text) {
        self.name = name
        self.value = value
        self.type = type
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = c.lenient(.name, "")
        value = c.lenient(.value, "")
        type = c.lenient(.type, .text)
        extra = decoder.unknownFields(Self.knownKeys)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(name, forKey: .name)
        try c.encode(value, forKey: .value)
        try c.encode(type, forKey: .type)
        try encoder.encodeUnknown(extra, known: Self.knownKeys)
    }
}

public struct PasswordChange: Codable, Equatable, Sendable {
    public var password = ""
    public var changedAt: Int64 = 0
    /// Fields this app doesn't know (a newer app's), written back unchanged.
    public var extra: [String: JSON] = [:]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case password, changedAt = "changed_at"
    }
    private static let knownKeys = Set(CodingKeys.allCases.map(\.rawValue))

    public init(password: String, changedAt: Int64) {
        self.password = password
        self.changedAt = changedAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        password = c.lenient(.password, "")
        changedAt = c.lenient(.changedAt, 0)
        extra = decoder.unknownFields(Self.knownKeys)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(password, forKey: .password)
        try c.encode(changedAt, forKey: .changedAt)
        try encoder.encodeUnknown(extra, known: Self.knownKeys)
    }
}

/// Item JSON in and out of the core.
public enum ItemCodec {
    public static func decode(_ json: String) throws -> Item {
        try JSONDecoder().decode(Item.self, from: Data(json.utf8))
    }

    /// `format` is left to the core when unknown (it stamps the current format on encrypt).
    public static func encode(_ item: Item) -> String {
        let e = JSONEncoder()
        e.outputFormatting = [.withoutEscapingSlashes]
        return String(decoding: (try? e.encode(item)) ?? Data("{}".utf8), as: UTF8.self)
    }
}

/// Any key, for the fields this app doesn't know.
struct AnyKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

extension Decoder {
    /// The object's fields whose keys aren't in `known`, as written (`[:]` for a non-object).
    func unknownFields(_ known: Set<String>) -> [String: JSON] {
        guard let all = try? container(keyedBy: AnyKey.self) else { return [:] }
        var out: [String: JSON] = [:]
        for k in all.allKeys where !known.contains(k.stringValue) {
            if let v = try? all.decode(JSON.self, forKey: k) { out[k.stringValue] = v }
        }
        return out
    }
}

extension Encoder {
    /// Write `extra` next to the known fields (a key the type knows is never written from it).
    func encodeUnknown(_ extra: [String: JSON], known: Set<String>) throws {
        guard !extra.isEmpty else { return }
        var rest = container(keyedBy: AnyKey.self)
        for (k, v) in extra where !known.contains(k) { try rest.encode(v, forKey: AnyKey(stringValue: k)) }
    }
}

extension KeyedDecodingContainer {
    /// The value at `key`, or `fallback` when it is missing, null or has the wrong type.
    func lenient<T: Decodable>(_ key: Key, _ fallback: T) -> T {
        ((try? decodeIfPresent(T.self, forKey: key)) ?? nil) ?? fallback
    }
}
