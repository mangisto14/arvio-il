import { blockedHost, corsHeaders, decodeMediaHeaders, handleMedia, originRejected, readTextCapped, type RelayEnv } from "./mediaRelay";

type Env = RelayEnv & {
  RESOLVER_KV?: KVNamespace;
  ALLOWED_ORIGINS?: string;
  /** "off" disables the /api/tmdb edge cache (and its upstream fallback origin). */
  TMDB_EDGE_CACHE?: string;
  SOURCE_CACHE_TTL_SECONDS?: string;
  ADDON_TIMEOUT_MS?: string;
  ADDON_EXTENDED_TIMEOUT_MS?: string;
  TRAKT_CLIENT_ID?: string;
  TRAKT_CLIENT_SECRET?: string;
  TMDB_API_KEY?: string;
};

// Trakt device-token exchange from the Worker. The Netlify backend's egress IP
// is Cloudflare-challenged by Trakt; the Worker (Cloudflare-origin) is not. The
// client secret lives here as a Worker secret and never touches the browser.
async function traktDeviceToken(request: Request, env: Env): Promise<Response> {
  const body = await request.json<{ code?: string }>().catch(() => null);
  if (!body?.code) return json({ error: "Missing device code" }, request, env, 400);
  if (!env.TRAKT_CLIENT_ID || !env.TRAKT_CLIENT_SECRET) {
    return json({ error: "Trakt is not configured on the resolver" }, request, env, 500);
  }
  const upstream = await fetch("https://api.trakt.tv/oauth/device/token", {
    method: "POST",
    headers: { "content-type": "application/json", "trakt-api-version": "2" },
    body: JSON.stringify({
      code: body.code,
      client_id: env.TRAKT_CLIENT_ID,
      client_secret: env.TRAKT_CLIENT_SECRET
    })
  });
  const text = await upstream.text();
  return new Response(text, {
    status: upstream.status,
    headers: {
      "content-type": upstream.headers.get("content-type") ?? "application/json",
      "cache-control": "no-store",
      ...corsHeaders(request, env)
    }
  });
}

type MediaType = "movie" | "tv";

type AddonCatalog = {
  type: string;
  id: string;
  name: string;
};

type InstalledAddon = {
  id: string;
  name: string;
  version?: string;
  manifestUrl: string;
  catalogs?: AddonCatalog[];
  resources?: Array<string | { name?: string; types?: string[]; idPrefixes?: string[] }>;
  types?: string[];
  idPrefixes?: string[];
  enabled?: boolean;
};

type MediaItem = {
  id: number;
  title: string;
  mediaType: MediaType;
  imdbId?: string | null;
};

type SubtitleTrack = {
  id?: string;
  url: string;
  lang?: string;
  label?: string;
  provider?: string;
  isEmbedded?: boolean;
  isForced?: boolean;
};

type RawStream = {
  name?: string;
  title?: string;
  url?: string;
  externalUrl?: string;
  ytId?: string;
  infoHash?: string;
  fileIdx?: number;
  behaviorHints?: StreamSource["behaviorHints"];
  subtitles?: SubtitleTrack[];
  sources?: string[];
  description?: string;
  size?: string;
  sizeBytes?: number;
};

type StreamSource = {
  source: string;
  addonName: string;
  addonId?: string;
  quality?: string;
  size?: string;
  sizeBytes?: number | null;
  url?: string | null;
  infoHash?: string | null;
  fileIdx?: number | null;
  behaviorHints?: {
    notWebReady?: boolean;
    cached?: boolean | null;
    bingeGroup?: string | null;
    directUrl?: string | null;
    url?: string | null;
    externalUrl?: string | null;
    videoHash?: string | null;
    videoSize?: number | null;
    proxyHeaders?: {
      request?: Record<string, string>;
      response?: Record<string, string>;
    } | null;
    filename?: string | null;
    browserPlayable?: boolean;
    iosPlayable?: boolean;
    externalPlayerRecommended?: boolean;
  } | null;
  subtitles?: SubtitleTrack[];
  sources?: string[];
  description?: string | null;
};

type SourcesRequest = {
  addons?: InstalledAddon[];
  item?: MediaItem;
  season?: number;
  episode?: number;
};

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const NDJSON_HEADERS = { "content-type": "application/x-ndjson; charset=utf-8" };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders(request, env) });

    try {
      // Edge cache for the app's TMDB metadata calls (route: web.arvio.tv/api/tmdb/*).
      // Serving these from Cloudflare keeps the several-hundred-request startup
      // burst off Netlify entirely — Netlify's per-IP abuse limiter once flagged a
      // household IP and every app boot re-triggered it (white screen / "No
      // episodes found"). Misses go to the stable netlify.app hostname from
      // Cloudflare egress, so client IPs never hit Netlify's counters for TMDB.
      if (url.pathname.startsWith("/api/tmdb/") && request.method === "GET" && env.TMDB_EDGE_CACHE !== "off") {
        return tmdbEdgeCache(request, env);
      }
      // Generic JSON API relay for allowlisted hosts (debrid APIs, cinemeta,
      // mdblist): these lack CORS so the browser needs a relay, and running it
      // here instead of Netlify's /api/proxy keeps those function invocations
      // and their (large) response bandwidth off the Netlify bill.
      if (url.pathname === "/proxy" && (request.method === "GET" || request.method === "POST")) {
        return apiProxy(request, env);
      }
      if (url.pathname === "/health") {
        return json({ ok: true, service: "arvio-resolver" }, request, env);
      }
      if (url.pathname === "/sources" && request.method === "POST") {
        return sources(request, env);
      }
      if (url.pathname === "/subtitle" && request.method === "GET") {
        return subtitle(request, env);
      }
      if (url.pathname === "/media" && (request.method === "GET" || request.method === "HEAD")) {
        return handleMedia(request, env);
      }
      if (url.pathname === "/launch" && request.method === "GET") {
        return launchPage(request, env);
      }
      if (url.pathname === "/trakt/device/token" && request.method === "POST") {
        return traktDeviceToken(request, env);
      }
      return json({ error: "Not found" }, request, env, 404);
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : "Resolver error" }, request, env, 500);
    }
  }
};

// Cache-first proxy for /api/tmdb/* on web.arvio.tv. Hits are served from the
// Cloudflare edge cache; misses go STRAIGHT to api.themoviedb.org (with the
// worker's TMDB_API_KEY secret) so TMDB traffic never touches Netlify at all —
// previously every miss cost TWO Netlify function invocations (the site's
// /api/tmdb route plus the auth site's tmdb-proxy behind it), the single
// biggest credits burner. The netlify.app hostname stays as a fallback origin
// for when TMDB itself is unreachable or no key is configured.
const TMDB_FALLBACK_ORIGIN = "https://arvio-web.netlify.app";

async function tmdbEdgeCache(request: Request, env: Env): Promise<Response> {
  const input = new URL(request.url);
  const cache = caches.default;
  const cacheKey = new Request(`https://web.arvio.tv${input.pathname}${input.search}`, { method: "GET" });
  const hit = await cache.match(cacheKey);
  if (hit) {
    const response = new Response(hit.body, hit);
    response.headers.set("x-arvio-edge", "hit");
    return response;
  }

  let upstream: Response | null = null;
  if (env.TMDB_API_KEY) {
    const direct = new URL(`https://api.themoviedb.org/3/${input.pathname.replace(/^\/api\/tmdb\//, "")}`);
    input.searchParams.forEach((value, key) => {
      if (key !== "cv") direct.searchParams.set(key, value);
    });
    direct.searchParams.set("api_key", env.TMDB_API_KEY);
    try {
      upstream = await fetch(direct.toString(), {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(12_000)
      });
      if (!upstream.ok && upstream.status !== 404) upstream = null;
    } catch {
      upstream = null;
    }
  }
  if (!upstream) {
    try {
      upstream = await fetch(`${TMDB_FALLBACK_ORIGIN}${input.pathname}${input.search}`, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(15_000)
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error instanceof Error ? error.message : "TMDB origin unreachable" }), {
        status: 502,
        headers: JSON_HEADERS
      });
    }
  }
  const response = new Response(upstream.body, upstream);
  response.headers.set("x-arvio-edge", "miss");
  response.headers.set("access-control-allow-origin", "*");
  if (upstream.ok) {
    response.headers.set("cache-control", "public, max-age=300, s-maxage=21600");
    await cache.put(cacheKey, response.clone());
  }
  return response;
}

// Hosts /proxy may relay to. Keep this tight — an open relay invites abuse.
// Debrid APIs carry the user's own bearer token; cinemeta/mdblist are public
// catalog data (their GETs are edge-cached below since they rarely change).
const PROXY_ALLOWED_HOSTS = new Set([
  "api.torbox.app",
  "api.real-debrid.com",
  "api.alldebrid.com",
  "www.premiumize.me",
  "v3-cinemeta.strem.io",
  "mdblist.com",
  // Trakt: the app's own Netlify functions are blocked by Trakt's Cloudflare
  // (server IPs get an "Attention Required" page), which kills Continue
  // Watching on the web. The Android app sidesteps this by calling Trakt
  // directly from the device; the web client tries direct too and falls back
  // here, where the egress IP is Cloudflare's rather than Netlify's.
  "api.trakt.tv"
]);
const PROXY_CACHEABLE_HOSTS = new Set(["v3-cinemeta.strem.io", "mdblist.com"]);

async function apiProxy(request: Request, env: Env) {
  const input = new URL(request.url);
  const raw = input.searchParams.get("url");
  if (!raw) return json({ error: "Missing url" }, request, env, 400);
  let target: URL;
  try {
    target = new URL(raw);
  } catch {
    return json({ error: "Invalid url" }, request, env, 400);
  }
  if (target.protocol !== "https:" || !PROXY_ALLOWED_HOSTS.has(target.hostname)) {
    return json({ error: "Host not allowed" }, request, env, 400);
  }
  const origin = request.headers.get("origin");
  if (origin) {
    const allowed = (env.ALLOWED_ORIGINS ?? "").split(",").map((value) => value.trim()).filter(Boolean);
    if (allowed.length && !allowed.includes(origin)) {
      return json({ error: "Origin not allowed" }, request, env, 403);
    }
  }

  const cacheable = request.method === "GET" && PROXY_CACHEABLE_HOSTS.has(target.hostname);
  const cache = caches.default;
  const cacheKey = new Request(`https://resolve.arvio.tv/proxy?url=${encodeURIComponent(target.toString())}`, { method: "GET" });
  if (cacheable) {
    const hit = await cache.match(cacheKey);
    if (hit) {
      const response = new Response(hit.body, hit);
      response.headers.set("x-arvio-edge", "hit");
      return response;
    }
  }

  const forwarded = new Headers({ accept: "application/json" });
  for (const [key, value] of Object.entries(decodeMediaHeaders(input.searchParams.get("h")))) {
    // trakt-api-* identify the calling app to Trakt and are required on every
    // Trakt call; without them Trakt answers 403 regardless of the bearer token.
    if (/^(authorization|content-type|user-agent|x-api-key|trakt-api-version|trakt-api-key)$/i.test(key)) forwarded.set(key, value);
  }
  let upstream: Response;
  try {
    upstream = await fetch(target.toString(), {
      method: request.method,
      headers: forwarded,
      body: request.method === "POST" ? await request.text() : undefined,
      signal: AbortSignal.timeout(25_000)
    });
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "Upstream fetch failed" }, request, env, 502);
  }
  const headers = new Headers(corsHeaders(request, env));
  headers.set("content-type", upstream.headers.get("content-type") ?? "application/json");
  headers.set("cache-control", "no-store");
  const response = new Response(upstream.body, { status: upstream.status, headers });
  if (cacheable && upstream.ok) {
    response.headers.set("cache-control", "public, max-age=300, s-maxage=21600");
    await cache.put(cacheKey, response.clone());
    response.headers.set("x-arvio-edge", "miss");
  }
  return response;
}

async function sources(request: Request, env: Env) {
  const payload = await request.json<SourcesRequest>().catch(() => null);
  if (!payload?.item) return json({ error: "Missing item" }, request, env, 400);

  const addons = (payload.addons ?? []).filter((addon) =>
    addon.enabled !== false &&
    Boolean(manifestUrlFor(addon)) &&
    supportsResource(addon, "stream")
  );

  const cacheKey = await sourceCacheKey(payload);
  const cached = await env.RESOLVER_KV?.get(cacheKey, "json") as StreamSource[] | null;
  if (cached?.length) {
    return json({ type: "final", cached: true, streams: cached }, request, env);
  }

  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  const write = async (value: unknown) => writer.write(encoder.encode(`${JSON.stringify(value)}\n`));

  void (async () => {
    let aggregate: StreamSource[] = [];
    await write({ type: "started", addonCount: addons.length });
    await Promise.all(addons.map(async (addon) => {
      const batch = await queryAddonStreams(addon, payload.item!, payload.season, payload.episode, env);
      if (!batch.length) return;
      aggregate = sortStreams(dedupeStreams([...aggregate, ...batch])
        .filter((stream) => stream.url || stream.infoHash || stream.description || stream.source));
      await write({ type: "batch", addonId: addon.id, addonName: addon.name, batch, streams: aggregate });
    }));
    if (aggregate.length && env.RESOLVER_KV) {
      await env.RESOLVER_KV.put(cacheKey, JSON.stringify(aggregate), {
        expirationTtl: ttl(env)
      }).catch(() => undefined);
    }
    await write({ type: "final", streams: aggregate });
    await writer.close();
  })().catch(async (error) => {
    await write({ type: "error", error: error instanceof Error ? error.message : "Resolver stream failed" }).catch(() => undefined);
    await writer.close().catch(() => undefined);
  });

  return new Response(readable, {
    headers: {
      ...NDJSON_HEADERS,
      ...corsHeaders(request, env),
      "cache-control": "no-store"
    }
  });
}

async function queryAddonStreams(addon: InstalledAddon, item: MediaItem, season: number | undefined, episode: number | undefined, env: Env) {
  const type = item.mediaType === "tv" ? "series" : "movie";
  const types = streamRequestTypes(addon, type);
  const ids = streamIds(item, season, episode);
  const { base, query } = addonBaseUrl(manifestUrlFor(addon));
  for (const id of ids) {
    if (!addonSupportsId(addon, id)) continue;
    for (const requestType of types) {
      if (!addonSupportsType(addon, requestType)) continue;
      const url = `${base}/stream/${requestType}/${encodeURIComponent(id)}.json${query ? `?${query}` : ""}`;
      const response = await fetchWithTimeout(url, env, addon).catch(() => null);
      if (!response?.ok) continue;
      const payload = await response.json<{ streams?: RawStream[] }>().catch(() => null);
      const streams = (payload?.streams ?? []).map((stream) => normalizeStream(stream, addon));
      if (streams.length > 0) return streams;
    }
  }
  return [] as StreamSource[];
}

async function subtitle(request: Request, env: Env) {
  const input = new URL(request.url);
  const raw = input.searchParams.get("url");
  if (!raw) return json({ error: "Missing url" }, request, env, 400);
  let target: URL;
  try {
    target = new URL(raw);
  } catch {
    return json({ error: "Invalid url" }, request, env, 400);
  }
  if (!["http:", "https:"].includes(target.protocol)) return json({ error: "Unsupported subtitle protocol" }, request, env, 400);
  if (originRejected(request, env)) return json({ error: "Origin not allowed" }, request, env, 403);
  if (target.username || target.password || blockedHost(target.hostname)) return json({ error: "Subtitle target not allowed" }, request, env, 403);

  let response: Response;
  try {
    response = await fetch(target, { signal: AbortSignal.timeout(20_000) });
  } catch {
    return json({ error: "Subtitle unavailable" }, request, env, 502);
  }
  if (response.url && blockedHost(new URL(response.url).hostname)) return json({ error: "Subtitle target not allowed" }, request, env, 403);
  const text = await readTextCapped(response.body, 5 * 1024 * 1024);
  if (text === null) return json({ error: "Subtitle exceeds the size limit" }, request, env, 502);
  const webvtt = text.trimStart().startsWith("WEBVTT") ? text : srtToVtt(text);
  return new Response(webvtt, {
    status: response.ok ? 200 : response.status,
    headers: {
      "content-type": "text/vtt; charset=utf-8",
      "cache-control": "public, max-age=3600",
      ...corsHeaders(request, env)
    }
  });
}

// Interstitial that opens an external-player URL scheme from a real Safari
// context. iOS home-screen webapps (standalone PWAs) silently drop custom-
// scheme navigations — but the in-app browser sheet they open for https links
// CAN launch app schemes (with the native "Open in …?" prompt). The PWA
// navigates here; this page fires the scheme and offers a manual button.
function launchPage(request: Request, env: Env) {
  const input = new URL(request.url);
  const to = input.searchParams.get("to") ?? "";
  if (!/^(vlc-x-callback|infuse|outplayer):\/\//i.test(to)) {
    return json({ error: "Unsupported launch target" }, request, env, 400);
  }
  const app = /^infuse:/i.test(to) ? "Infuse" : /^outplayer:/i.test(to) ? "Outplayer" : "VLC";
  const href = to.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Opening ${app}…</title>
<style>
  body{background:#0b0b0f;color:#ececf1;font-family:system-ui,-apple-system,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center}
  a.btn{display:inline-block;margin-top:18px;padding:14px 30px;border-radius:12px;background:#fff;color:#000;font-weight:700;font-size:17px;text-decoration:none}
  p{opacity:.7;font-size:14px;max-width:340px;line-height:1.5}
</style></head>
<body><div>
  <h2 style="font-weight:600">Opening ${app}…</h2>
  <p>If nothing happens, tap the button below. Make sure ${app} is installed.</p>
  <a class="btn" href="${href}">Open in ${app}</a>
</div>
<script>setTimeout(function(){ window.location.href = ${JSON.stringify(to)}; }, 80);</script>
</body></html>`;
  return new Response(html, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }
  });
}

function streamIds(item: MediaItem, season?: number, episode?: number) {
  const ids: string[] = [];
  const hasEpisode = item.mediaType === "tv" && season && episode;
  if (item.imdbId?.startsWith("tt")) {
    ids.push(hasEpisode ? `${item.imdbId}:${season}:${episode}` : item.imdbId);
  }
  ids.push(hasEpisode ? `tmdb:${item.id}:${season}:${episode}` : `tmdb:${item.id}`);
  return Array.from(new Set(ids));
}

function streamRequestTypes(addon: InstalledAddon, requestedType: "movie" | "series") {
  const aliases = requestedType === "series" ? ["series", "tv", "show"] : ["movie", "film"];
  return aliases.filter((type) => addonSupportsType(addon, type));
}

function normalizeStream(stream: RawStream, addon: InstalledAddon): StreamSource {
  const text = [stream.title, stream.name, stream.description, stream.size].filter(Boolean).join(" ");
  const url = streamUrl(stream);
  const browser = browserCompatibility(url, text);
  return {
    source: stream.name ?? stream.title ?? addon.name,
    addonName: addon.name,
    addonId: addon.id,
    quality: detectQuality(text),
    size: stream.size ?? sizeLabel(stream.sizeBytes ?? stream.behaviorHints?.videoSize ?? null),
    sizeBytes: stream.sizeBytes ?? stream.behaviorHints?.videoSize ?? null,
    url,
    infoHash: stream.infoHash ?? null,
    fileIdx: stream.fileIdx ?? null,
    behaviorHints: {
      ...(stream.behaviorHints ?? {}),
      notWebReady: !url && Boolean(stream.infoHash || stream.ytId || stream.behaviorHints?.videoHash),
      browserPlayable: browser.browserPlayable,
      iosPlayable: browser.iosPlayable,
      externalPlayerRecommended: browser.externalPlayerRecommended
    },
    subtitles: stream.subtitles ?? [],
    sources: stream.sources ?? [],
    description: stream.description ?? stream.title ?? null
  };
}

function streamUrl(stream: RawStream) {
  const candidates = [
    stream.url,
    stream.externalUrl,
    stream.behaviorHints?.directUrl,
    stream.behaviorHints?.url,
    stream.behaviorHints?.externalUrl
  ];
  for (const candidate of candidates) {
    const value = typeof candidate === "string" ? candidate.trim() : "";
    if (!value) continue;
    if (value.startsWith("//")) return `https:${value}`;
    if (/^https?:\/\//i.test(value)) return value;
  }
  return null;
}

function browserCompatibility(url: string | null, text: string) {
  const lower = `${url ?? ""} ${text}`.toLowerCase();
  const hls = lower.includes(".m3u8") || lower.includes("mpegurl");
  const mp4 = /\.(mp4|m4v|mov)(?:[?#]|$)/i.test(url ?? "");
  const unsupportedContainer = /\.(mkv|avi|wmv|flv)(?:[?#]|$)/i.test(url ?? "");
  const unsupportedAudio = /\b(dts|truehd|eac3|e-ac-3|atmos truehd)\b/i.test(text);
  const unsupportedBrowserVideo = /\b(x265|h\.265|h265|hevc|av1|dolby vision|dv)\b/i.test(text);
  return {
    browserPlayable: Boolean(url && (hls || mp4) && !unsupportedContainer && !unsupportedAudio && !unsupportedBrowserVideo),
    iosPlayable: Boolean(url && (hls || mp4) && !unsupportedContainer && !unsupportedAudio),
    externalPlayerRecommended: Boolean(url && (!hls && !mp4 || unsupportedContainer || unsupportedAudio || unsupportedBrowserVideo))
  };
}

function manifestUrlFor(addon: InstalledAddon) {
  const compatible = addon as InstalledAddon & { url?: string; transportUrl?: string };
  const raw = compatible.manifestUrl || compatible.url || compatible.transportUrl || "";
  if (!raw) return "";
  const trimmed = raw.trim();
  try {
    const url = new URL(trimmed);
    if (url.pathname.endsWith("/manifest.json")) return url.toString();
    url.pathname = `${url.pathname.replace(/\/+$/, "")}/manifest.json`;
    return url.toString();
  } catch {
    return trimmed.endsWith("/manifest.json") ? trimmed : `${trimmed.replace(/\/+$/, "")}/manifest.json`;
  }
}

function addonBaseUrl(manifestUrl: string) {
  try {
    const url = new URL(manifestUrl);
    const query = url.searchParams.toString();
    url.search = "";
    url.pathname = url.pathname.replace(/\/manifest\.json$/, "").replace(/\/+$/, "");
    return { base: url.toString().replace(/\/+$/, ""), query };
  } catch {
    const [path, query = ""] = manifestUrl.split("?");
    return { base: path.replace(/\/manifest\.json$/, "").replace(/\/+$/, ""), query };
  }
}

function supportsResource(addon: InstalledAddon, resource: string) {
  if (!Array.isArray(addon.resources) || addon.resources.length === 0) return true;
  return addon.resources
    .map((item) => typeof item === "string" ? item : item?.name)
    .filter(Boolean)
    .includes(resource);
}

function addonSupportsType(addon: InstalledAddon, requestedType: string) {
  const declared = new Set<string>();
  const add = (value: unknown) => {
    if (typeof value === "string" && value.trim()) declared.add(value.trim().toLowerCase());
  };
  addon.types?.forEach(add);
  addon.resources?.forEach((resource) => {
    if (typeof resource !== "string") resource.types?.forEach(add);
  });
  if (!declared.size) return true;
  const aliases = requestedType === "series" || requestedType === "tv" || requestedType === "show"
    ? ["series", "tv", "show"]
    : requestedType === "movie" || requestedType === "film"
      ? ["movie", "film"]
      : [requestedType];
  return aliases.some((alias) => declared.has(alias));
}

function addonSupportsId(addon: InstalledAddon, id: string) {
  const prefixes = [
    ...(addon.idPrefixes ?? []),
    ...(addon.resources ?? []).flatMap((resource) => typeof resource === "string" ? [] : resource.idPrefixes ?? [])
  ].map((prefix) => prefix.trim()).filter(Boolean);
  if (!prefixes.length) return true;
  return prefixes.some((prefix) =>
    id.toLowerCase().startsWith(prefix.toLowerCase()) ||
    (!prefix.endsWith(":") && id.toLowerCase().startsWith(`${prefix.toLowerCase()}:`))
  );
}

async function fetchWithTimeout(url: string, env: Env, addon?: InstalledAddon) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs(env, addon));
  try {
    return await fetch(url, {
      headers: {
        accept: "application/json,text/plain,*/*",
        "user-agent": userAgent()
      },
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
}

function dedupeStreams(streams: StreamSource[]) {
  const seen = new Set<string>();
  return streams.filter((stream) => {
    const key = [
      stream.addonId,
      stream.url ?? "",
      stream.infoHash ?? "",
      stream.fileIdx ?? "",
      stream.source,
      stream.description ?? ""
    ].join("|");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function sortStreams(streams: StreamSource[]) {
  return streams.sort((a, b) => streamScore(b) - streamScore(a));
}

function streamScore(stream: StreamSource) {
  const text = `${stream.quality ?? ""} ${stream.source} ${stream.description ?? ""}`.toLowerCase();
  let score = 0;
  if (stream.behaviorHints?.iosPlayable) score += 140;
  else if (stream.behaviorHints?.browserPlayable) score += 120;
  else if (stream.url) score += 80;
  if (stream.behaviorHints?.cached) score += 80;
  if (text.includes("2160") || text.includes("4k")) score += 60;
  if (text.includes("1080")) score += 45;
  if (text.includes("720")) score += 25;
  if (text.includes("hdr")) score += 12;
  if (text.includes("cam")) score -= 80;
  if (stream.infoHash && !stream.url) score -= 50;
  if (stream.sizeBytes) score += Math.min(25, stream.sizeBytes / 1_000_000_000);
  return score;
}

function detectQuality(value: string) {
  const text = value.toLowerCase();
  if (text.includes("2160") || text.includes("4k")) return "4K";
  if (text.includes("1080")) return "1080p";
  if (text.includes("720")) return "720p";
  if (text.includes("hdr")) return "HDR";
  return "HD";
}

function sizeLabel(bytes?: number | null) {
  if (!bytes || !Number.isFinite(bytes)) return "";
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
  if (bytes >= 1_000_000) return `${Math.round(bytes / 1_000_000)} MB`;
  return "";
}

function srtToVtt(input: string) {
  return `WEBVTT\n\n${input.replace(/\r/g, "").replace(/(\d\d:\d\d:\d\d),(\d\d\d)/g, "$1.$2")}`;
}

async function sourceCacheKey(payload: SourcesRequest) {
  const normalized = JSON.stringify({
    item: payload.item,
    season: payload.season ?? null,
    episode: payload.episode ?? null,
    addons: (payload.addons ?? []).map((addon) => ({
      id: addon.id,
      manifestUrl: manifestUrlFor(addon),
      enabled: addon.enabled !== false
    }))
  });
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalized));
  return `sources:v2:${Array.from(new Uint8Array(hash)).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function json(value: unknown, request: Request, env: Env, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      ...JSON_HEADERS,
      ...corsHeaders(request, env),
      "cache-control": "no-store"
    }
  });
}

function ttl(env: Env) {
  const parsed = Number(env.SOURCE_CACHE_TTL_SECONDS);
  return Number.isFinite(parsed) && parsed > 0 ? Math.round(parsed) : 180;
}

function timeoutMs(env: Env, addon?: InstalledAddon) {
  const source = addonNeedsExtendedTimeout(addon) ? env.ADDON_EXTENDED_TIMEOUT_MS : env.ADDON_TIMEOUT_MS;
  const parsed = Number(source);
  if (Number.isFinite(parsed) && parsed > 0) return Math.round(parsed);
  return addonNeedsExtendedTimeout(addon) ? 35000 : 15000;
}

function addonNeedsExtendedTimeout(addon?: InstalledAddon) {
  const text = [
    addon?.id,
    addon?.name,
    addon?.manifestUrl
  ].filter(Boolean).join(" ").toLowerCase();
  return /torrentio|torbox|real-?debrid|premiumize|debrid|mediafusion|comet|aiostream|flix-stream|flixnest|flickystream|pengu/.test(text);
}

function userAgent() {
  return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
}
