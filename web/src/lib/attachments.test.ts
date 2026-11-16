import { describe, expect, it } from "vitest";
import {
  LEFTOVER_AFTER,
  MIB,
  addAttachments,
  anyAttachments,
  attachmentLimitMb,
  cleanFileName,
  downloadName,
  leftovers,
  mergeAttachments,
  missingOnServer,
  readAttachments,
  readStoredAttachments,
  removeAttachment,
  sameId,
  setAttachments,
  stripAttachments,
  tooLarge,
  withAttachmentsOf,
} from "./attachments";
import { emptyItem, type Attachment, type Item } from "./types";

const A = "0b6b7c1e-0f55-4f2e-9d55-3c3a3c3a3c3a";
const B = "1c7c8d2f-1066-4a3f-8e66-4d4b4d4b4d4b";
const C = "2d8d9e30-2177-4b40-9f77-5e5c5e5c5e5c";
const file = (id: string, name = "report.pdf", size = 1200): Attachment => ({ id, name, size, key: `key-${id}` });
const item = (attachments?: unknown): Item => ({ ...emptyItem("note"), name: "Passport", ...(attachments === undefined ? {} : { attachments }) }) as Item;

/** The core's encrypted size: 20 + size + 16 per 64 KiB chunk (at least one). */
const encSize = (n: number) => 20 + n + 16 * Math.max(1, Math.ceil(n / 65536));

describe("readAttachments", () => {
  it("lists the files of an item", () => {
    expect(readAttachments(item([file(A), file(B, "scan.png", 5)]))).toEqual([file(A), file(B, "scan.png", 5)]);
    expect(readAttachments(item())).toEqual([]);
    expect(readAttachments(null)).toEqual([]);
    expect(readAttachments({ attachments: "nope" })).toEqual([]);
  });

  it("leaves out malformed entries and repeated ids, and fills in what can be guessed", () => {
    const list = readAttachments(
      item([
        file(A),
        { ...file(A), name: "again.pdf" },
        { id: A.toUpperCase(), name: "upper", size: 1, key: "k" },
        { id: "not-a-uuid", name: "x", size: 1, key: "k" },
        { id: B, name: "no key", size: 1 },
        { id: C, name: "  ", size: -4, key: "k" },
        null,
        "text",
      ]),
    );
    expect(list).toEqual([file(A), { id: C, name: "Attachment", size: 0, key: "k" }]);
  });

  it("keeps ids as written: the file's encryption is bound to them", () => {
    const upper = A.toUpperCase();
    expect(readAttachments(item([{ id: upper, name: "a", size: 1, key: "k" }]))[0].id).toBe(upper);
    expect(sameId(upper, A)).toBe(true);
    expect(sameId(A, B)).toBe(false);
  });
});

describe("changing the list", () => {
  it("adds and removes entries, keeping fields a newer app wrote", () => {
    const newer = { ...file(A), mime: "application/pdf" };
    const withB = addAttachments(item([newer]), [file(B)]);
    expect(withB.attachments).toEqual([newer, file(B)]);
    const withoutA = removeAttachment(withB, A.toUpperCase());
    expect(withoutA.attachments).toEqual([file(B)]);
  });

  it("drops the field when the last file goes, and doesn't change the item it was given", () => {
    const one = item([file(A)]);
    const none = removeAttachment(one, A);
    expect("attachments" in none).toBe(false);
    expect(one.attachments).toEqual([file(A)]);
    expect("attachments" in setAttachments(item(), [])).toBe(false);
  });

  it("gives an edited draft the list of the item as last synced", () => {
    const draft = { ...item([file(A)]), notes: "edited" };
    const synced = item([file(A), file(B)]);
    expect(withAttachmentsOf(draft, synced)).toEqual({ ...draft, attachments: [file(A), file(B)] });
    expect("attachments" in withAttachmentsOf(draft, item())).toBe(false);
  });

  it("merges two lists by id, the first one's entries first", () => {
    expect(mergeAttachments(item([file(A), file(B)]), item([file(B, "older name"), file(C)]))).toEqual([file(A), file(B), file(C)]);
    expect(mergeAttachments(item(), item([file(C)]))).toEqual([file(C)]);
    expect(mergeAttachments(null, undefined)).toEqual([]);
  });
});

describe("exports and imports", () => {
  it("strips the list, and with it every file key", () => {
    const stripped = stripAttachments(item([file(A)]));
    expect("attachments" in stripped).toBe(false);
    expect(JSON.stringify(stripped)).not.toContain("key-");
    const plain = item();
    expect(stripAttachments(plain)).toBe(plain);
  });

  it("tells whether any item lists a file", () => {
    expect(anyAttachments([item(), item([file(A)])])).toBe(true);
    expect(anyAttachments([item(), item([])])).toBe(false);
  });
});

describe("sizes", () => {
  it("compares the encrypted size with the server's limit", () => {
    expect(tooLarge(MIB, 1, encSize)).toBe(true); // 1 MiB of plaintext is a little more encrypted
    expect(tooLarge(MIB - 20 - 16 * 16, 1, encSize)).toBe(false);
    expect(tooLarge(MIB - 20 - 16 * 16 + 1, 1, encSize)).toBe(true);
    expect(tooLarge(10 * MIB, null, encSize)).toBe(false);
    expect(tooLarge(10, 0, encSize)).toBe(false);
  });

  it("reads the limit from /api/config", () => {
    expect(attachmentLimitMb({ max_attachment_mb: 100 })).toBe(100);
    expect(attachmentLimitMb({ max_attachment_mb: 0 })).toBeNull();
    expect(attachmentLimitMb({ max_attachment_mb: "100" })).toBeNull();
    expect(attachmentLimitMb(undefined)).toBeNull();
  });
});

describe("file names", () => {
  it("keeps a picked file's name without folders or control characters", () => {
    expect(cleanFileName("report.pdf")).toBe("report.pdf");
    expect(cleanFileName("C:\\Users\\me\\scan 1.png")).toBe("scan 1.png");
    expect(cleanFileName("a\u0000b\u001fc.txt")).toBe("abc.txt");
    expect(cleanFileName("   ")).toBe("Attachment");
    expect(cleanFileName("x".repeat(300) + ".txt")).toHaveLength(255);
  });

  it("saves under a name file systems accept", () => {
    expect(downloadName("report.pdf")).toBe("report.pdf");
    expect(downloadName("../../etc/passwd")).toBe("_.._etc_passwd");
    expect(downloadName('a:b*c?"d<e>f|g')).toBe("a_b_c__d_e_f_g");
    expect(downloadName("...")).toBe("attachment");
    expect(downloadName("")).toBe("attachment");
  });

  it("shows and saves a name that can't pretend to be another file", () => {
    // A right-to-left override shows "invoice\u202Efdp.exe" as "invoiceexe.pdf": it goes, and so does every other format character.
    expect(cleanFileName("invoice\u202Efdp.exe")).toBe("invoicefdp.exe");
    expect(downloadName("invoice\u202Efdp.exe")).toBe("invoicefdp.exe");
    expect(downloadName("\u2066a\u2067b\u2068c\u2069.txt\u200E\u200F\uFEFF")).toBe("abc.txt");
    expect(downloadName("scan\u200B.p\u200Ddf")).toBe("scan.pdf");
    // Windows drops trailing dots and spaces: "report.exe. " would really be "report.exe".
    expect(cleanFileName("report.exe. . ")).toBe("report.exe");
    expect(downloadName("report.exe. . ")).toBe("report.exe");
    // White space can't push the extension out of sight.
    expect(downloadName("invoice.pdf\u3000    \u00A0  .exe")).toBe("invoice.pdf .exe");
    expect(downloadName("a\u0000b\u0085c\u2028.txt")).toBe("abc.txt");
  });

  it("never saves under a Windows device name", () => {
    for (const name of ["CON", "con.txt", "Nul.tar.gz", "AUX", "prn.doc", "COM1.txt", "lpt9", "COM0.log", "LPT\u00B9.txt", "con .txt"])
      expect(downloadName(name)).toBe(`_${name}`);
    for (const name of ["CONSOLE.txt", "COM10.txt", "aux file.txt", "icon.png", "my con.txt"]) expect(downloadName(name)).toBe(name);
  });

  it("keeps the extension when a long name is cut", () => {
    const saved = downloadName(`${"a".repeat(300)}.pdf`);
    expect(Array.from(saved)).toHaveLength(200);
    expect(saved.endsWith("a.pdf")).toBe(true);
    expect(Array.from(downloadName("b".repeat(300)))).toHaveLength(200);
    expect(cleanFileName(`${"c".repeat(300)}.tar.gz`).endsWith("c.gz")).toBe(true);
  });

  it("shows the files of an item under clean names", () => {
    expect(readAttachments(item([{ ...file(A), name: "pay\u202Egpj.exe" }]))[0].name).toBe("paygpj.exe");
    expect(readAttachments(item([{ ...file(A), name: "\u202E" }]))[0].name).toBe("Attachment");
    expect(readAttachments(item([{ ...file(A), name: 42 }]))[0].name).toBe("Attachment");
  });
});

describe("the server's list", () => {
  const stored = readStoredAttachments({
    attachments: [
      { id: A, size: 1236, state: "ready", updated_at: 1000 },
      { id: B, size: 80, state: "pending", updated_at: 1000 },
      { id: C, size: 80, state: "ready", updated_at: 5000 },
      { id: "bad", size: 1, state: "ready" },
      { id: A, size: 1, state: "deleted" },
    ],
  });

  it("reads it, leaving out malformed entries", () => {
    expect(stored.map((s) => s.id)).toEqual([A, B, C]);
    expect(readStoredAttachments({})).toEqual([]);
    expect(readStoredAttachments(null)).toEqual([]);
  });

  it("finds listed files the server doesn't have ready", () => {
    expect(missingOnServer([file(A.toUpperCase()), file(B), file("3e9eaf41-3288-4c51-8088-6f6d6f6d6f6d")], stored)).toEqual(
      new Set([B, "3e9eaf41-3288-4c51-8088-6f6d6f6d6f6d"]),
    );
  });

  it("finds finished uploads no item lists, once nobody can still be attaching them", () => {
    const listed = item([file(A)]);
    expect(leftovers(listed, stored, 1000 + LEFTOVER_AFTER).map((s) => s.id)).toEqual([]);
    expect(leftovers(listed, stored, 5000 + LEFTOVER_AFTER).map((s) => s.id)).toEqual([C]);
    // Pending uploads are left to the server, which deletes them after an hour.
    expect(leftovers(item(), stored, 99_999).map((s) => s.id)).toEqual([A, C]);
  });
});
