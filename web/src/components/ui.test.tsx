import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AccountPicture, SiteIcon } from "./ui";

describe("SiteIcon", () => {
  it("shows the same globe glyph for every login when website icons are off (no letter, no request)", () => {
    const a = renderToStaticMarkup(<SiteIcon host="github.com" name="GitHub" server="https://vault.example" enabled={false} />);
    const b = renderToStaticMarkup(<SiteIcon host="example.org" name="Zebra" server="https://vault.example" enabled={false} />);
    expect(a).toBe(b);
    expect(a).toContain("glyph");
    expect(a).toContain("<svg");
    expect(a).not.toContain("<img");
    expect(a).not.toMatch(/>[GZ]</);
  });

  it("asks the icon service when icons are on, with the item's letter until the icon loads", () => {
    const html = renderToStaticMarkup(<SiteIcon host="github.com" name="GitHub" server="https://vault.example" />);
    expect(html).toContain("https://vault.example/api/icons/github.com");
    expect(html).not.toContain("glyph");
    expect(html).toContain("G");
  });
});

describe("AccountPicture", () => {
  it("shows the initials when there is no picture", () => {
    const html = renderToStaticMarkup(<AccountPicture name="Alex Morgan" email="alex@example.com" />);
    expect(html).toContain(">AM<");
    expect(html).toContain('aria-hidden="true"');
    expect(html).not.toContain("<img");
  });
});
