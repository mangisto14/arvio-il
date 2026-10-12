/**
 * Live TV playback diagnostics.
 *
 * A playlist can load (it is fetched server-side through /api/proxy) while its
 * channels can never play: media is requested by the browser itself, and the
 * hosted proxy refuses media. On an https deployment an http:// channel is then
 * blocked as mixed content on every rung of the ladder unless an HTTPS media
 * relay (the resolver worker) is configured, and the docked player could only
 * say "could not be played". These helpers name that and similar known causes.
 *
 * Summaries deliberately contain no host, path or query: IPTV links commonly
 * carry the subscriber's username, password or token.
 */

export type StreamKind = "hls" | "dash" | "mpegts" | "file" | "unknown";

export type StreamUrlSummary = {
  /** Lower-case scheme without the colon, or "invalid". */
  scheme: string;
  kind: StreamKind;
};

/** Known reasons a live channel cannot play in this browser page, if any. */
export type LivePlaybackBlocker = "invalid-url" | "unsupported-scheme" | "insecure-without-relay";

export type LivePlaybackContext = {
  /** `location.protocol` of the ARVIO page, e.g. "https:". */
  pageProtocol: string;
  /** An HTTPS media relay (resolver worker) or the app media proxy is available. */
  hasRelay: boolean;
};

const BROWSER_SCHEMES = new Set(["http", "https"]);
const LOOPBACK_HOST = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])$/i;

function parse(url: string | null | undefined) {
  if (typeof url !== "string" || !url.trim()) return null;
  try {
    // No base URL: a relative playlist entry would otherwise silently resolve
    // against the ARVIO origin instead of the provider.
    return new URL(url.trim());
  } catch {
    return null;
  }
}

function streamKind(url: URL): StreamKind {
  let path = url.pathname;
  try { path = decodeURIComponent(path); } catch { /* Keep the encoded path. */ }
  if (/\.m3u8$/i.test(path) || /^(?:m3u8|hls)$/i.test(url.searchParams.get("output") ?? "")) return "hls";
  if (/\.mpd$/i.test(path)) return "dash";
  if (/\.ts$/i.test(path) || /^(?:ts|mpegts)$/i.test(url.searchParams.get("output") ?? "")) return "mpegts";
  if (/\.(?:mp4|m4v|mov|mkv|webm)$/i.test(path)) return "file";
  return "unknown";
}

export function summarizeStreamUrl(url: string | null | undefined): StreamUrlSummary {
  const parsed = parse(url);
  if (!parsed) return { scheme: "invalid", kind: "unknown" };
  return { scheme: parsed.protocol.replace(/:$/, "").toLowerCase(), kind: streamKind(parsed) };
}

/** Browsers block http subresources on an https page; loopback is exempt. */
export function isMixedContent(pageProtocol: string, url: string | null | undefined) {
  const parsed = parse(url);
  return pageProtocol === "https:" && parsed?.protocol === "http:" && !LOOPBACK_HOST.test(parsed.hostname);
}

export function livePlaybackBlocker(url: string | null | undefined, context: LivePlaybackContext): LivePlaybackBlocker | null {
  const parsed = parse(url);
  if (!parsed) return "invalid-url";
  if (!BROWSER_SCHEMES.has(parsed.protocol.replace(/:$/, "").toLowerCase())) return "unsupported-scheme";
  if (!context.hasRelay && isMixedContent(context.pageProtocol, url)) return "insecure-without-relay";
  return null;
}

/** Where a ladder attempt is sent, without revealing the target itself. */
export function playbackAttemptRoute(attemptUrl: string, appOrigin: string, relayUrl: string) {
  const parsed = parse(attemptUrl) ?? parse(new URL(attemptUrl, appOrigin || "https://arvio.invalid").toString());
  if (!parsed) return "invalid";
  if (relayUrl && parsed.toString().startsWith(`${relayUrl.replace(/\/+$/, "")}/media`)) return "relay";
  if (parsed.origin === appOrigin && parsed.pathname === "/api/proxy") return `app-proxy:${parsed.searchParams.get("rewrite") ?? "media"}`;
  return "direct";
}

/** One console line per event; every field is a fixed token, never a URL. */
export function playbackDiagnosticLine(event: string, fields: Record<string, string | number | boolean | undefined>) {
  const parts = Object.entries(fields)
    .filter(([, value]) => value !== undefined && value !== "")
    .map(([name, value]) => `${name}=${String(value).replace(/[^\w.:-]/g, "_").slice(0, 60)}`);
  return `[ARVIO IPTV] ${event}${parts.length ? ` ${parts.join(" ")}` : ""}`;
}
