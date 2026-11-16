import PassAuthCore
import PassAuthKit
import XCTest

/// Attachment rules (every case of the web vault's `attachments.test.ts`), the item JSON keeping
/// the list and other apps' fields, and the transfers against a fake server (the cases of
/// `transfer.test.ts` that apply to files read from and written to disk).
final class AttachmentsTests: XCTestCase {
    private let A = "0b6b7c1e-0f55-4f2e-9d55-3c3a3c3a3c3a"
    private let B = "1c7c8d2f-1066-4a3f-8e66-4d4b4d4b4d4b"
    private let C = "2d8d9e30-2177-4b40-9f77-5e5c5e5c5e5c"

    private func file(_ id: String, _ name: String = "report.pdf", _ size: Int64 = 1200) -> Attachment {
        Attachment(id: id, name: name, size: size, key: "key-\(id)")
    }

    private func item(_ attachments: [JSON]? = nil) -> Item {
        var i = Item.empty(.note, now: 1)
        i.name = "Passport"
        i.attachments = attachments
        return i
    }

    /// The core's encrypted size: 20 + size + 16 per 64 KiB chunk (at least one).
    private let encSize: (Int64) -> Int64 = { n in 20 + n + 16 * max(1, (n + 65535) / 65536) }

    // MARK: readAttachments

    func testListsTheFilesOfAnItem() {
        XCTAssertEqual(AttachmentList.read(item([file(A).json, file(B, "scan.png", 5).json])), [file(A), file(B, "scan.png", 5)])
        XCTAssertEqual(AttachmentList.read(item()), [])
        XCTAssertEqual(AttachmentList.read(nil as Item?), [])
    }

    func testLeavesOutMalformedEntriesAndRepeatedIds() {
        let list = AttachmentList.read(item([
            file(A).json,
            ["id": .string(A), "name": "again.pdf", "size": 1200, "key": .string("key-\(A)")],
            ["id": .string(A.uppercased()), "name": "upper", "size": 1, "key": "k"],
            ["id": "not-a-uuid", "name": "x", "size": 1, "key": "k"],
            ["id": .string(B), "name": "no key", "size": 1],
            ["id": .string(C), "name": "  ", "size": -4, "key": "k"],
            nil,
            "text",
        ]))
        XCTAssertEqual(list, [file(A), Attachment(id: C, name: "Attachment", size: 0, key: "k")])
    }

    func testKeepsIdsAsWritten() {
        let upper = A.uppercased()
        XCTAssertEqual(AttachmentList.read(item([["id": .string(upper), "name": "a", "size": 1, "key": "k"]]))[0].id, upper)
        XCTAssertTrue(AttachmentList.sameId(upper, A))
        XCTAssertFalse(AttachmentList.sameId(A, B))
    }

    // MARK: changing the list

    func testAddsAndRemovesEntriesKeepingFieldsANewerAppWrote() {
        var newer = file(A).json
        if case .object(var o) = newer { o["mime"] = "application/pdf"; newer = .object(o) }
        let withB = AttachmentList.add(item([newer]), [file(B)])
        XCTAssertEqual(withB.attachments, [newer, file(B).json])
        XCTAssertEqual(AttachmentList.remove(withB, A.uppercased()).attachments, [file(B).json])
    }

    func testDropsTheFieldWhenTheLastFileGoes() throws {
        let one = item([file(A).json])
        let none = AttachmentList.remove(one, A)
        XCTAssertNil(none.attachments)
        XCTAssertEqual(one.attachments, [file(A).json])
        XCTAssertNil(AttachmentList.set(item(), []).attachments)
        // Left out of the JSON, as for an item that never had files.
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(ItemCodec.encode(none).utf8)) as? NSDictionary)
        XCTAssertNil(json["attachments"])
    }

    func testGivesAnEditedDraftTheListOfTheItemAsLastSynced() {
        var draft = item([file(A).json])
        draft.notes = "edited"
        let synced = item([file(A).json, file(B).json])
        var expected = draft
        expected.attachments = [file(A).json, file(B).json]
        XCTAssertEqual(AttachmentList.withAttachments(of: synced, draft), expected)
        XCTAssertNil(AttachmentList.withAttachments(of: item(), draft).attachments)
    }

    func testMergesTwoListsByIdTheFirstOnesEntriesFirst() {
        XCTAssertEqual(AttachmentList.merge([file(A).json, file(B).json], [file(B, "older name").json, file(C).json]), [file(A).json, file(B).json, file(C).json])
        XCTAssertEqual(AttachmentList.merge(nil, [file(C).json]), [file(C).json])
        XCTAssertEqual(AttachmentList.merge(nil, nil), [])
    }

    // MARK: exports

    func testStripsTheListAndWithItEveryFileKey() {
        let stripped = AttachmentList.strip(item([file(A).json]))
        XCTAssertNil(stripped.attachments)
        XCTAssertFalse(ItemCodec.encode(stripped).contains("key-"))
        XCTAssertEqual(AttachmentList.strip(item()), item())
    }

    func testTellsWhetherAnyItemListsAFile() {
        XCTAssertTrue(AttachmentList.any([item(), item([file(A).json])]))
        XCTAssertFalse(AttachmentList.any([item(), item([])]))
    }

    // MARK: sizes

    func testComparesTheEncryptedSizeWithTheServersLimit() {
        let mib = AttachmentList.mib
        XCTAssertTrue(AttachmentList.tooLarge(mib, maxMb: 1, encryptedSize: encSize))
        XCTAssertFalse(AttachmentList.tooLarge(mib - 20 - 16 * 16, maxMb: 1, encryptedSize: encSize))
        XCTAssertTrue(AttachmentList.tooLarge(mib - 20 - 16 * 16 + 1, maxMb: 1, encryptedSize: encSize))
        XCTAssertFalse(AttachmentList.tooLarge(10 * mib, maxMb: nil, encryptedSize: encSize))
        XCTAssertFalse(AttachmentList.tooLarge(10, maxMb: 0, encryptedSize: encSize))
    }

    func testTheCoresEncryptedSizeIsTheOneTheTestsAssume() {
        for n: Int64 in [0, 1, 65535, 65536, 65537, 1024 * 1024] { XCTAssertEqual(AttachmentList.encryptedSize(n), encSize(n), "\(n)") }
    }

    func testReadsTheLimitFromConfig() {
        XCTAssertEqual(AttachmentList.limitMb(["max_attachment_mb": 100]), 100)
        XCTAssertNil(AttachmentList.limitMb(["max_attachment_mb": 0]))
        XCTAssertNil(AttachmentList.limitMb(["max_attachment_mb": "100"]))
        XCTAssertNil(AttachmentList.limitMb(nil))
    }

    /// Any JSON number can come from a crafted item or a server: never a crash (Int64(1e300)
    /// traps), sizes and limits kept in a range that can be added up and multiplied.
    func testCraftedNumbersDontCrash() throws {
        let huge = try JSON.parse(#"{"a":1e300,"b":-1e300,"c":9.3e18,"d":-9.3e18,"e":12.9,"f":-0.5,"g":"7"}"#)
        XCTAssertNil(JSON.wholeInt64(1e300))
        XCTAssertNil(JSON.wholeInt64(.nan))
        XCTAssertNil(JSON.wholeInt64(.infinity))
        XCTAssertNil(JSON.wholeInt64(9.3e18))
        XCTAssertEqual(JSON.wholeInt64(12.9), 12)
        XCTAssertEqual(JSON.wholeInt64(-12.9), -12)
        XCTAssertNil(huge["a"]?.number)
        XCTAssertNil(huge["d"]?.number)
        XCTAssertEqual(huge["e"]?.number, 12)
        XCTAssertNil(huge["g"]?.number)
        XCTAssertEqual(huge["a"]?.int, 0)
        XCTAssertEqual(huge["b"]?.int, 0)
        XCTAssertEqual(huge["g"]?.int, 7)

        let entries = try JSON.parse(#"[{"id":"\#(A)","name":"a","size":1e300,"key":"k"},{"id":"\#(B)","name":"b","size":9223372036854775807,"key":"k"},{"id":"\#(C)","name":"c","size":-1e300,"key":"k"}]"#)
        let files = AttachmentList.read(entries.array)
        XCTAssertEqual(files.map(\.size), [0, AttachmentList.maxSize, 0])
        XCTAssertEqual(AttachmentList.limitMb(try JSON.parse(#"{"max_attachment_mb":1e300}"#)), 1 << 30)
        XCTAssertEqual(AttachmentList.limitMb(try JSON.parse(#"{"max_attachment_mb":9223372036854775807}"#)), 1 << 30)
        XCTAssertFalse(AttachmentList.tooLarge(1 << 40, maxMb: 1 << 30) { $0 })
        let listed = StoredAttachment.list(try JSON.parse(#"{"attachments":[{"id":"\#(A)","state":"ready","size":1e300,"updated_at":-9223372036854775808},{"id":"\#(B)","state":"ready","size":9223372036854775807,"updated_at":1e300}]}"#))
        XCTAssertEqual(listed.map(\.size), [0, 1 << 50])
        // An unreadable time counts as long ago.
        XCTAssertEqual(AttachmentList.leftovers(item(), listed, now: 1_700_000_000).map(\.id), [A, B])
    }

    // MARK: file names

    func testKeepsAPickedFilesNameWithoutFoldersOrControlCharacters() {
        XCTAssertEqual(AttachmentList.cleanFileName("report.pdf"), "report.pdf")
        XCTAssertEqual(AttachmentList.cleanFileName("C:\\Users\\me\\scan 1.png"), "scan 1.png")
        XCTAssertEqual(AttachmentList.cleanFileName("a\u{0000}b\u{001F}c.txt"), "abc.txt")
        XCTAssertEqual(AttachmentList.cleanFileName("   "), "Attachment")
        XCTAssertEqual(AttachmentList.cleanFileName(String(repeating: "x", count: 300) + ".txt").unicodeScalars.count, 255)
    }

    func testSavesUnderANameFileSystemsAccept() {
        XCTAssertEqual(AttachmentList.downloadName("report.pdf"), "report.pdf")
        XCTAssertEqual(AttachmentList.downloadName("../../etc/passwd"), "_.._etc_passwd")
        XCTAssertEqual(AttachmentList.downloadName("a:b*c?\"d<e>f|g"), "a_b_c__d_e_f_g")
        XCTAssertEqual(AttachmentList.downloadName("..."), "attachment")
        XCTAssertEqual(AttachmentList.downloadName(""), "attachment")
    }

    func testShowsAndSavesANameThatCantPretendToBeAnotherFile() {
        XCTAssertEqual(AttachmentList.cleanFileName("invoice\u{202E}fdp.exe"), "invoicefdp.exe")
        XCTAssertEqual(AttachmentList.downloadName("invoice\u{202E}fdp.exe"), "invoicefdp.exe")
        XCTAssertEqual(AttachmentList.downloadName("\u{2066}a\u{2067}b\u{2068}c\u{2069}.txt\u{200E}\u{200F}\u{FEFF}"), "abc.txt")
        XCTAssertEqual(AttachmentList.downloadName("scan\u{200B}.p\u{200D}df"), "scan.pdf")
        XCTAssertEqual(AttachmentList.cleanFileName("report.exe. . "), "report.exe")
        XCTAssertEqual(AttachmentList.downloadName("report.exe. . "), "report.exe")
        XCTAssertEqual(AttachmentList.downloadName("invoice.pdf\u{3000}    \u{00A0}  .exe"), "invoice.pdf .exe")
        XCTAssertEqual(AttachmentList.downloadName("a\u{0000}b\u{0085}c\u{2028}.txt"), "abc.txt")
    }

    func testNeverSavesUnderAWindowsDeviceName() {
        for name in ["CON", "con.txt", "Nul.tar.gz", "AUX", "prn.doc", "COM1.txt", "lpt9", "COM0.log", "LPT\u{00B9}.txt", "con .txt"] {
            XCTAssertEqual(AttachmentList.downloadName(name), "_\(name)", name)
        }
        for name in ["CONSOLE.txt", "COM10.txt", "aux file.txt", "icon.png", "my con.txt"] {
            XCTAssertEqual(AttachmentList.downloadName(name), name, name)
        }
    }

    func testKeepsTheExtensionWhenALongNameIsCut() {
        let saved = AttachmentList.downloadName(String(repeating: "a", count: 300) + ".pdf")
        XCTAssertEqual(saved.unicodeScalars.count, 200)
        XCTAssertTrue(saved.hasSuffix("a.pdf"))
        XCTAssertEqual(AttachmentList.downloadName(String(repeating: "b", count: 300)).unicodeScalars.count, 200)
        XCTAssertTrue(AttachmentList.cleanFileName(String(repeating: "c", count: 300) + ".tar.gz").hasSuffix("c.gz"))
    }

    func testShowsTheFilesOfAnItemUnderCleanNames() {
        func named(_ n: JSON) -> JSON { ["id": .string(A), "name": n, "size": 1200, "key": "k"] }
        XCTAssertEqual(AttachmentList.read(item([named("pay\u{202E}gpj.exe")]))[0].name, "paygpj.exe")
        XCTAssertEqual(AttachmentList.read(item([named("\u{202E}")]))[0].name, "Attachment")
        XCTAssertEqual(AttachmentList.read(item([named(42)]))[0].name, "Attachment")
    }

    // MARK: the server's list

    private var stored: [StoredAttachment] {
        StoredAttachment.list(["attachments": [
            ["id": .string(A), "size": 1236, "state": "ready", "updated_at": 1000],
            ["id": .string(B), "size": 80, "state": "pending", "updated_at": 1000],
            ["id": .string(C), "size": 80, "state": "ready", "updated_at": 5000],
            ["id": "bad", "size": 1, "state": "ready"],
            ["id": .string(A), "size": 1, "state": "deleted"],
        ]])
    }

    func testReadsTheServersListLeavingOutMalformedEntries() {
        XCTAssertEqual(stored.map(\.id), [A, B, C])
        XCTAssertEqual(StoredAttachment.list([:]), [])
        XCTAssertEqual(StoredAttachment.list(nil), [])
    }

    func testFindsListedFilesTheServerDoesntHaveReady() {
        let other = "3e9eaf41-3288-4c51-8088-6f6d6f6d6f6d"
        XCTAssertEqual(AttachmentList.missingOnServer([file(A.uppercased()), file(B), file(other)], stored), [B, other])
    }

    func testFindsFinishedUploadsNoItemLists() {
        let listed = item([file(A).json])
        XCTAssertEqual(AttachmentList.leftovers(listed, stored, now: 1000 + AttachmentList.leftoverAfter).map(\.id), [])
        XCTAssertEqual(AttachmentList.leftovers(listed, stored, now: 5000 + AttachmentList.leftoverAfter).map(\.id), [C])
        XCTAssertEqual(AttachmentList.leftovers(item(), stored, now: 99_999).map(\.id), [A, C])
    }

    // MARK: the item JSON

    func testItemsKeepTheirFileListAndOtherAppsFieldsThroughAnEdit() throws {
        let json = #"{"name":"Scan","notes":"","attachments":[{"id":"\#(A)","name":"a.pdf","size":3,"key":"k","mime":"application/pdf"}],"future":{"x":[1,2]},"login":null}"#
        var item = try ItemCodec.decode(json)
        XCTAssertEqual(AttachmentList.read(item).map(\.name), ["a.pdf"])
        XCTAssertEqual(item.extra["future"], ["x": [1, 2]])
        item.notes = "edited"
        let back = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(ItemCodec.encode(item).utf8)) as? [String: Any])
        let list = try XCTUnwrap(back["attachments"] as? [[String: Any]])
        XCTAssertEqual(list.first?["mime"] as? String, "application/pdf")
        XCTAssertEqual((back["future"] as? [String: Any])?["x"] as? [Int], [1, 2])
        XCTAssertEqual(back["notes"] as? String, "edited")
        XCTAssertEqual(try ItemCodec.decode(ItemCodec.encode(item)), item)
    }

    // MARK: transfers

    private final class FakeTransport: AttachmentTransport, @unchecked Sendable {
        var log: [String] = []
        var putBytes = Data()
        var failPut: Error?
        var failRegister: Error?
        var download: Result<URL, TransferError>?
        var onPut: (() -> Void)?

        func register(itemId: String, attachmentId: String, size: Int64) async throws {
            log.append("register \(itemId) \(attachmentId) \(size)")
            if let failRegister { throw failRegister }
        }
        func put(attachmentId: String, file: URL, size: Int64, progress: @escaping @Sendable (Double) -> Void) async throws {
            putBytes = try Data(contentsOf: file)
            log.append("put \(attachmentId) \(size) \(putBytes.count)")
            onPut?()
            // URLSession stops a request whose task was cancelled.
            try Task.checkCancellation()
            if let failPut { throw failPut }
        }
        func discard(attachmentId: String) async throws { log.append("discard \(attachmentId)") }
        func get(path: String) async throws -> Result<URL, TransferError> {
            log.append("get \(path)")
            return download ?? .failure(.missing)
        }
    }

    private var dir: URL!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("attachments-test-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    private func transfer(_ t: FakeTransport) -> AttachmentTransfer {
        var x = AttachmentTransfer(transport: t, directory: dir.appendingPathComponent("work"))
        x.newId = { "00000000-0000-4000-8000-000000000001" }
        return x
    }

    private func source(_ bytes: Data) throws -> URL {
        let url = dir.appendingPathComponent("source-\(UUID().uuidString)")
        try bytes.write(to: url)
        return url
    }

    private let item1 = "11111111-1111-4111-8111-111111111111"

    func testRegistersTheEncryptedSizeThenSendsTheEncryptedFileAndItDecryptsBack() async throws {
        let t = FakeTransport()
        let plain = Data((0..<(3 * 1024 * 1024 + 17)).map { UInt8($0 % 251) })
        let src = try source(plain)
        let done = try await transfer(t).upload(src, size: Int64(plain.count), itemId: item1)
        let enc = AttachmentList.encryptedSize(Int64(plain.count))
        XCTAssertEqual(t.log, ["register \(item1) \(done.id) \(enc)", "put \(done.id) \(enc) \(enc)"])
        XCTAssertEqual(try fileDecrypt(key: done.key, itemId: item1, attachmentId: done.id, ciphertext: t.putBytes), plain)
        // The encrypted copy is gone once sent.
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.appendingPathComponent("work").path), [])
    }

    func testEncryptsAnEmptyFileToo() async throws {
        let t = FakeTransport()
        let done = try await transfer(t).upload(try source(Data()), size: 0, itemId: item1)
        XCTAssertEqual(t.putBytes.count, Int(AttachmentList.encryptedSize(0)))
        XCTAssertEqual(try fileDecrypt(key: done.key, itemId: item1, attachmentId: done.id, ciphertext: t.putBytes), Data())
    }

    func testDeletesTheAttachmentAgainWhenTheUploadFails() async throws {
        let t = FakeTransport()
        t.failPut = ApiError(status: 500, code: "internal", message: "boom")
        do {
            _ = try await transfer(t).upload(try source(Data("abc".utf8)), size: 3, itemId: item1)
            XCTFail("expected a failure")
        } catch let e as ApiError {
            XCTAssertEqual(e.status, 500)
        }
        XCTAssertEqual(t.log.last, "discard 00000000-0000-4000-8000-000000000001")
    }

    func testDeletesTheAttachmentAgainWhenCancelledAndSaysItWasCancelled() async throws {
        let t = FakeTransport()
        let x = transfer(t)
        let src = try source(Data(repeating: 1, count: 10))
        let itemId = item1
        let task = Task { try await x.upload(src, size: 10, itemId: itemId) }
        t.onPut = { task.cancel() }
        do {
            _ = try await task.value
            XCTFail("expected a cancel")
        } catch {
            XCTAssertEqual(error as? TransferError, .cancelled)
        }
        XCTAssertTrue(t.log.contains("discard 00000000-0000-4000-8000-000000000001"))
    }

    func testRegistersNothingWhenCancelledBeforeItStartsAndDeletesNothingWhenRegisteringFails() async throws {
        let t = FakeTransport()
        let x = transfer(t)
        let src = try source(Data("abc".utf8))
        let itemId = item1
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await x.upload(src, size: 3, itemId: itemId)
        }
        _ = try? await task.value
        XCTAssertEqual(t.log, [])
        let failing = FakeTransport()
        failing.failRegister = ApiError(status: 403, code: "quota_exceeded", message: "attachment storage limit reached")
        do {
            _ = try await transfer(failing).upload(src, size: 3, itemId: item1)
            XCTFail("expected a failure")
        } catch let e as ApiError {
            XCTAssertEqual(errorMessage(e), attachmentQuotaMessage)
        }
        XCTAssertEqual(failing.log.count, 1)
    }

    func testReportsAFileThatCantBeRead() async throws {
        let t = FakeTransport()
        do {
            _ = try await transfer(t).upload(dir.appendingPathComponent("gone"), size: 3, itemId: item1)
            XCTFail("expected a failure")
        } catch {
            XCTAssertEqual(error as? TransferError, .unreadable)
        }
        XCTAssertEqual(t.log.last, "discard 00000000-0000-4000-8000-000000000001")
        // A file that changed size since it was picked can't be sent as registered.
        let changed = FakeTransport()
        do {
            _ = try await transfer(changed).upload(try source(Data("abcd".utf8)), size: 3, itemId: item1)
            XCTFail("expected a failure")
        } catch {
            XCTAssertEqual(error as? TransferError, .unreadable)
        }
    }

    private func encryptedFile(_ plain: Data, key: String, id: String) throws -> URL {
        try source(try fileEncrypt(key: key, itemId: item1, attachmentId: id, plaintext: plain))
    }

    func testDecryptsTheFileAndHandsItOverOnceItIsWhole() async throws {
        let key = try fileNewKey()
        let plain = Data((0..<(2 * 1024 * 1024 + 5)).map { UInt8($0 % 13) })
        let t = FakeTransport()
        t.download = .success(try encryptedFile(plain, key: key, id: A))
        let att = Attachment(id: A, name: "../report:1.pdf", size: Int64(plain.count), key: key)
        let out = try await transfer(t).download(att, itemId: item1, path: "/attachments/\(A)")
        XCTAssertEqual(out.lastPathComponent, "_report_1.pdf")
        XCTAssertEqual(try Data(contentsOf: out), plain)
        AttachmentTransfer.discardDownload(out)
        XCTAssertFalse(FileManager.default.fileExists(atPath: out.path))
    }

    func testThrowsEverythingAwayWhenTheFileIsntWholeOrDamaged() async throws {
        let key = try fileNewKey()
        let plain = Data(repeating: 7, count: 200_000)
        let whole = try fileEncrypt(key: key, itemId: item1, attachmentId: A, plaintext: plain)
        for broken in [whole.prefix(whole.count - 10), { var d = whole; d[100] ^= 1; return d }()] {
            let t = FakeTransport()
            t.download = .success(try source(Data(broken)))
            do {
                _ = try await transfer(t).download(Attachment(id: A, name: "a.bin", size: 200_000, key: key), itemId: item1, path: "/x")
                XCTFail("expected a failure")
            } catch {
                XCTAssertEqual(fileErrorMessage(error), "This file couldn't be decrypted: it is damaged or incomplete. Try again.")
            }
            let work = dir.appendingPathComponent("work")
            let left = (try? FileManager.default.contentsOfDirectory(atPath: work.path)) ?? []
            XCTAssertEqual(left, [], "nothing decrypted is left behind")
        }
    }

    func testSaysWhenTheServerDoesntHaveTheFile() async throws {
        let t = FakeTransport()
        t.download = .failure(.missing)
        do {
            _ = try await transfer(t).download(file(A), itemId: item1, path: "/attachments/\(A)")
            XCTFail("expected a failure")
        } catch {
            XCTAssertEqual(fileErrorMessage(error), "This file is no longer on the server.")
        }
    }

    func testWhichSaveFailuresAreWorthAnotherTry() {
        XCTAssertTrue(VaultRepository.retryAttachmentSave(ApiError(status: 409, code: "revision_conflict", message: "")))
        XCTAssertTrue(VaultRepository.retryAttachmentSave(ApiError(status: 429, code: "rate_limited", message: "")))
        XCTAssertTrue(VaultRepository.retryAttachmentSave(ApiError(status: 503, code: "error", message: "")))
        XCTAssertFalse(VaultRepository.retryAttachmentSave(ApiError(status: 507, code: "insufficient_storage", message: "")))
        XCTAssertFalse(VaultRepository.retryAttachmentSave(ApiError(status: 403, code: "quota_exceeded", message: "")))
        XCTAssertFalse(VaultRepository.retryAttachmentSave(UserError("locked")))
    }
}
