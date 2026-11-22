/** Whether the web vault shows website icons: the user's preference and the server's icon service together. */
import { hasFeature, type PublicConfig, usePublicConfig } from "./api";
import { useShowIcons } from "./prefs";

/**
 * Icons are shown when the user wants them and the server offers them. Servers announce the icon service as the
 * feature `icons`; until the first answer arrives the preference alone decides (a failed icon just falls back to the
 * letter avatar).
 */
export function siteIconsShown(wanted: boolean, config: PublicConfig | null): boolean {
  if (!wanted) return false;
  if (!config) return true;
  return hasFeature(config, "icons");
}

export function useSiteIconsShown(): boolean {
  return siteIconsShown(useShowIcons(), usePublicConfig());
}
