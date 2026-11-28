// Types for safari-manifest.mjs (used by build.mjs and test/safari-manifest.test.ts).
export const MIN_SAFARI: string;
// biome-ignore lint/suspicious/noExplicitAny: a manifest is free-form JSON
export function safariManifest(chrome: any, version: string): any;
export const SAFARI_KEYS: Record<string, string>;
