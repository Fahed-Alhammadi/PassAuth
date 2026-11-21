// Types for firefox-manifest.mjs (used by build.mjs and test/firefox-manifest.test.ts).
export const GECKO_ID: string;
export const MIN_FIREFOX: string;
// biome-ignore lint/suspicious/noExplicitAny: a manifest is free-form JSON
export function firefoxManifest(chrome: any): any;
