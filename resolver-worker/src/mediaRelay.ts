// Restricted HLS/media relay for /media.
//
// An https ARVIO page cannot load http:// IPTV media (mixed content), so the
// worker relays it. A relay that forwards any URL is an open proxy: the Origin
// header is only sent by fetch/XHR players (Safari's native HLS and curl send
// none), so CORS cannot authenticate anything. Instead:
//   - an unsigned request may only target a host in MEDIA_ALLOWED_HOSTS;
//   - URLs the worker itself writes into a relayed playlist (variants, keys,
//     init sections, segments) carry an HMAC signature with an expiry, so a
//     provider may redirect to or reference other hosts (edge IPs, CDNs)
//     without opening the relay to arbitrary targets.
// Missing configuration fails closed. Error responses never echo URLs: IPTV
// links carry subscriber credentials.

export type RelayEnv = {
  ALLOWED_ORIGINS?: string;
  MEDIA_ALLOWED_HOSTS?: string;
  MEDIA_SIGNING_KEY?: string;
  MEDIA_SIGNATURE_TTL_SECONDS?: string;
};

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

const MAX_REDIRECTS = 5;
const MAX_PLAYLIST_BYTES = 4 * 1024 * 1024;
const DEFAULT_SIGNATURE_TTL_SECONDS = 12 * 60 * 60;
const MIN_SIGNING_KEY_LENGTH = 32;
const UPSTREAM_TIMEOUT_MS = 30_000;
// Request headers a source may legitimately require (user-agent/referer
// allowlists on IPTV panels, declared addon headers).
const FORWARDED_HEADER = /^(user-agent|referer|origin|icy-metadata|authorization|cookie)$/i;
const CREDENTIAL_HEADER = /^(authorization|cookie)$/i;
// Ports Cloudflare's reverse proxy serves. A fetch to another port on a
// Cloudflare-proxied host is silently sent to the default port instead.
const CLOUDFLARE_PROXY_PORTS: Record<string, Set<string>> = {
  "http:": new Set(["80", "8080", "8880", "2052", "2082", "2086", "2095"]),
  "https:": new Set(["443", "2053", "2083", "2087", "2096", "8443"])
};
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Release an unneeded upstream body without waiting on the upstream. */
function discard(stream: { cancel(): Promise<void> } | null | undefined) {
  stream?.cancel().catch(() => undefined);
}

export function allowedOrigins(env: Pick<RelayEnv, "ALLOWED_ORIGINS">) {
  return (env.ALLOWED_ORIGINS ?? "").split(",").map((value) => value.trim()).filter(Boolean);
}

/** Echo only an allowlisted Origin; never fall back to "*". */
export function corsHeaders(request: Request, env: Pick<RelayEnv, "ALLOWED_ORIGINS">): Record<string, string> {
  const origin = request.headers.get("origin") ?? "";
  const allowed = allowedOrigins(env);
  const headers: Record<string, string> = {
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type,authorization,range",
    "vary": "origin"
  };
  const allowOrigin = allowed.includes(origin) ? origin : allowed[0];
  if (allowOrigin) headers["access-control-allow-origin"] = allowOrigin;
  return headers;
}

/** Requests from browsers' fetch/XHR carry Origin; it must then be allowlisted. */
export function originRejected(request: Request, env: Pick<RelayEnv, "ALLOWED_ORIGINS">) {
  const origin = request.headers.get("origin");
  return origin !== null && !allowedOrigins(env).includes(origin);
}

function relayError(message: string, status: number, request: Request, env: RelayEnv) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...corsHeaders(request, env) }
  });
}

/** Host patterns: "example.com" (exact) or "*.example.com" (subdomains only). */
export function hostAllowed(hostname: string, rawPatterns: string | undefined) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return (rawPatterns ?? "").split(",").map((value) => value.trim().toLowerCase()).filter(Boolean).some((pattern) =>
    pattern.startsWith("*.") ? host.endsWith(pattern.slice(1)) && host.length > pattern.length - 1 : host === pattern
  );
}

function ipv4Octets(host: string) {
  const parts = host.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return null;
  return parts.map(Number);
}

/**
 * Literal loopback, private, link-local, CGNAT, multicast and reserved
 * targets. Workers cannot resolve DNS before fetching, so a public name that
 * resolves to a private address is not detectable here; Cloudflare's edge does
 * not route to private networks, and global_fetch_strictly_public is set.
 */
export function blockedHost(hostname: string) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal") || host.endsWith(".local")) return true;
  const v4 = ipv4Octets(host);
  if (v4) {
    const [a, b] = v4;
    return a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0 && v4[2] === 0)
      || (a === 198 && (b === 18 || b === 19));
  }
  if (host.includes(":")) {
    if (host === "::" || host === "::1") return true;
    const mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return blockedHost(mapped[1]);
    if (/^::ffff:/.test(host)) return true;
    return /^(fc|fd|fe[89ab]|ff)/.test(host);
  }
  return false;
}

function signatureTtl(env: RelayEnv) {
  const parsed = Number(env.MEDIA_SIGNATURE_TTL_SECONDS);
  return Number.isFinite(parsed) && parsed >= 60 && parsed <= 7 * 24 * 3600 ? Math.round(parsed) : DEFAULT_SIGNATURE_TTL_SECONDS;
}

async function hmacKey(secret: string) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

function signedPayload(url: string, headersParam: string, expires: number) {
  return new TextEncoder().encode(`arvio-media-v1\n${expires}\n${url}\n${headersParam}`);
}

function toBase64Url(bytes: ArrayBuffer) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string) {
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

export async function signMediaUrl(secret: string, url: string, headersParam: string, expires: number) {
  return toBase64Url(await crypto.subtle.sign("HMAC", await hmacKey(secret), signedPayload(url, headersParam, expires)));
}

async function signatureValid(secret: string, url: string, headersParam: string, expires: number, signature: string) {
  const bytes = fromBase64Url(signature);
  if (!bytes || bytes.length !== 32) return false;
  // crypto.subtle.verify compares in constant time.
  return crypto.subtle.verify("HMAC", await hmacKey(secret), bytes, signedPayload(url, headersParam, expires));
}

export function decodeMediaHeaders(raw: string | null): Record<string, string> {
  if (!raw) return {};
  try {
    const decoded = JSON.parse(atob(raw.replace(/-/g, "+").replace(/_/g, "/")));
    if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) return {};
    return Object.fromEntries(Object.entries(decoded).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
  } catch {
    return {};
  }
}

function forwardedHeaders(headersParam: string | null, range: string | null) {
  const declared = decodeMediaHeaders(headersParam);
  const headers = new Headers({ accept: "*/*", "user-agent": "VLC/3.0.20 LibVLC/3.0.20" });
  for (const [key, value] of Object.entries(declared)) {
    if (FORWARDED_HEADER.test(key) && value.length <= 4096) headers.set(key, value);
  }
  if (range) headers.set("range", range);
  return headers;
}

type Upstream = { response: Response; finalUrl: URL };

async function fetchUpstream(target: URL, method: string, headers: Headers, fetchImpl: FetchLike): Promise<Upstream | { refused: string; status: number }> {
  let current = target;
  let currentHeaders = headers;
  let currentMethod = method;
  const signal = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!["http:", "https:"].includes(current.protocol) || current.username || current.password || blockedHost(current.hostname)) {
      return { refused: "Media target not allowed", status: 403 };
    }
    let response: Response;
    try {
      response = await fetchImpl(current.toString(), { method: currentMethod, headers: currentHeaders, redirect: "manual", signal });
    } catch {
      return { refused: "Upstream unavailable", status: 502 };
    }
    if (!REDIRECT_STATUSES.has(response.status)) {
      // A custom port on a Cloudflare-proxied host is not honoured; whatever
      // answered on the default port is not the stream that was asked for.
      const port = current.port;
      if (port && !CLOUDFLARE_PROXY_PORTS[current.protocol]?.has(port) && response.headers.has("cf-ray")) {
        discard(response.body);
        return { refused: "Upstream port is not reachable from Cloudflare", status: 502 };
      }
      return { response, finalUrl: current };
    }
    const location = response.headers.get("location");
    discard(response.body);
    if (!location || hop === MAX_REDIRECTS) return { refused: "Upstream redirect not followed", status: 502 };
    let next: URL;
    try { next = new URL(location, current); } catch { return { refused: "Upstream redirect not followed", status: 502 }; }
    if (next.origin !== current.origin) {
      // Never hand one server's credentials to another.
      currentHeaders = new Headers(currentHeaders);
      for (const key of [...currentHeaders.keys()]) if (CREDENTIAL_HEADER.test(key)) currentHeaders.delete(key);
    }
    if (response.status === 303) currentMethod = currentMethod === "HEAD" ? "HEAD" : "GET";
    current = next;
  }
  return { refused: "Upstream redirect not followed", status: 502 };
}

function looksBinaryType(contentType: string) {
  const type = contentType.split(";")[0].trim().toLowerCase();
  if (type.includes("mpegurl")) return false;
  return /^(video|audio|image|font)\//.test(type) || type === "application/mp4";
}

const textDecoder = () => new TextDecoder("utf-8");

/**
 * Reads only the start of a body to decide whether it is an HLS playlist.
 * Non-playlist bodies are passed on unchanged and still streamed.
 */
async function classifyBody(body: ReadableStream<Uint8Array>) {
  const reader = body.getReader();
  const head: Uint8Array[] = [];
  let length = 0;
  while (length < 16) {
    const chunk = await reader.read();
    if (chunk.done) break;
    head.push(chunk.value);
    length += chunk.value.byteLength;
  }
  const prefix = textDecoder().decode(concat(head)).replace(/^\uFEFF/, "").trimStart();
  return { reader, head, length, playlist: prefix.startsWith("#EXTM3U") };
}

function concat(chunks: Uint8Array[]) {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.byteLength; }
  return out;
}

function replayStream(head: Uint8Array[], reader: ReadableStreamDefaultReader<Uint8Array>) {
  let index = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (index < head.length) { controller.enqueue(head[index++]); return; }
      const chunk = await reader.read();
      if (chunk.done) controller.close();
      else controller.enqueue(chunk.value);
    },
    cancel(reason) { return reader.cancel(reason); }
  });
}

async function readCapped(head: Uint8Array[], length: number, reader: ReadableStreamDefaultReader<Uint8Array>, limit: number) {
  const chunks = [...head];
  let total = length;
  if (total > limit) { discard(reader); return null; }
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    total += chunk.value.byteLength;
    if (total > limit) { discard(reader); return null; }
    chunks.push(chunk.value);
  }
  return textDecoder().decode(concat(chunks));
}

/** Read a text body with a hard size limit; null when it is larger. */
export async function readTextCapped(body: ReadableStream<Uint8Array> | null, limit: number) {
  if (!body) return "";
  return readCapped([], 0, body.getReader(), limit);
}

/**
 * Rewrites every http(s) reference in a playlist — media/variant lines and
 * URI="…" attributes (EXT-X-KEY, EXT-X-MAP, EXT-X-MEDIA, EXT-X-PART, …) —
 * to signed, root-relative /media URLs on this worker. Relative references
 * resolve against the playlist's final URL after redirects. Other schemes
 * (skd://, data:) are left untouched.
 */
export async function rewritePlaylist(text: string, baseUrl: URL, headersParam: string, secret: string, expires: number) {
  const cache = new Map<string, string>();
  const relay = async (raw: string) => {
    const trimmed = raw.trim();
    if (!trimmed || /^(data|blob|skd):/i.test(trimmed)) return raw;
    let absolute: URL;
    try { absolute = new URL(trimmed, baseUrl); } catch { return raw; }
    if (!["http:", "https:"].includes(absolute.protocol)) return raw;
    const key = absolute.toString();
    const cached = cache.get(key);
    if (cached) return cached;
    const params = new URLSearchParams();
    params.set("url", key);
    if (headersParam) params.set("h", headersParam);
    params.set("exp", String(expires));
    params.set("sig", await signMediaUrl(secret, key, headersParam, expires));
    const relayed = `/media?${params.toString()}`;
    cache.set(key, relayed);
    return relayed;
  };
  const lines = text.split(/\r?\n/);
  const out: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) { out.push(line); continue; }
    if (!trimmed.startsWith("#")) { out.push(await relay(line)); continue; }
    const parts: string[] = [];
    let last = 0;
    for (const match of line.matchAll(/URI="([^"]+)"/g)) {
      parts.push(line.slice(last, match.index), `URI="${await relay(match[1])}"`);
      last = (match.index ?? 0) + match[0].length;
    }
    parts.push(line.slice(last));
    out.push(parts.join(""));
  }
  return out.join("\n");
}

export async function handleMedia(request: Request, env: RelayEnv, fetchImpl: FetchLike = fetch, now = () => Date.now()): Promise<Response> {
  const secret = env.MEDIA_SIGNING_KEY ?? "";
  if (!allowedOrigins(env).length || !(env.MEDIA_ALLOWED_HOSTS ?? "").trim() || secret.length < MIN_SIGNING_KEY_LENGTH) {
    return relayError("Media relay is not configured", 503, request, env);
  }
  if (originRejected(request, env)) return relayError("Origin not allowed", 403, request, env);

  const input = new URL(request.url);
  const raw = input.searchParams.get("url");
  if (!raw) return relayError("Missing url", 400, request, env);
  let target: URL;
  try { target = new URL(raw); } catch { return relayError("Invalid url", 400, request, env); }
  if (!["http:", "https:"].includes(target.protocol) || target.username || target.password || blockedHost(target.hostname)) {
    return relayError("Media target not allowed", 403, request, env);
  }

  const headersParam = input.searchParams.get("h") ?? "";
  const signature = input.searchParams.get("sig");
  const wantsDownload = input.searchParams.get("dl") === "1";
  if (signature !== null) {
    const expires = Number(input.searchParams.get("exp"));
    const nowSeconds = Math.floor(now() / 1000);
    const valid = !wantsDownload && Number.isInteger(expires) && expires > nowSeconds
      && expires <= nowSeconds + signatureTtl(env) + 300
      && await signatureValid(secret, target.toString(), headersParam, expires, signature);
    if (!valid) return relayError("Media link expired or invalid", 403, request, env);
  } else if (!hostAllowed(target.hostname, env.MEDIA_ALLOWED_HOSTS)) {
    return relayError("Media target not allowed", 403, request, env);
  }

  let upstream = await fetchUpstream(target, request.method, forwardedHeaders(headersParam, request.headers.get("range")), fetchImpl);
  if ("refused" in upstream) return relayError(upstream.refused, upstream.status, request, env);
  // Media elements (Chromium, and Safari's byte-range probes) may open even a
  // playlist URL with "Range: bytes=0-…". A partial playlist cannot be
  // rewritten, so a small non-binary range from offset 0 is fetched whole once.
  // Answering a range request with a full 200 is valid HTTP.
  if (request.method === "GET" && !wantsDownload && upstream.response.status === 206) {
    const contentRange = upstream.response.headers.get("content-range") ?? "";
    const total = Number(/\/(\d+)$/.exec(contentRange)?.[1]);
    if (/^bytes 0-/.test(contentRange) && Number.isFinite(total) && total <= MAX_PLAYLIST_BYTES
      && !looksBinaryType(upstream.response.headers.get("content-type") ?? "")) {
      discard(upstream.response.body);
      upstream = await fetchUpstream(target, "GET", forwardedHeaders(headersParam, null), fetchImpl);
      if ("refused" in upstream) return relayError(upstream.refused, upstream.status, request, env);
    }
  }
  const { response, finalUrl } = upstream;
  const contentType = response.headers.get("content-type") ?? "";

  const mayBePlaylist = request.method === "GET" && !wantsDownload && response.status === 200 && response.body
    && (contentType.toLowerCase().includes("mpegurl") || /\.m3u8?$/i.test(finalUrl.pathname) || !looksBinaryType(contentType));
  let body: ReadableStream<Uint8Array> | null = request.method === "HEAD" ? null : response.body;
  if (mayBePlaylist && response.body) {
    const sniffed = await classifyBody(response.body);
    if (sniffed.playlist) {
      const text = await readCapped(sniffed.head, sniffed.length, sniffed.reader, MAX_PLAYLIST_BYTES);
      if (text === null) return relayError("Playlist exceeds the size limit", 502, request, env);
      const expires = Math.floor(now() / 1000) + signatureTtl(env);
      return new Response(await rewritePlaylist(text, finalUrl, headersParam, secret, expires), {
        status: 200,
        headers: { "content-type": "application/vnd.apple.mpegurl", "cache-control": "no-store", ...corsHeaders(request, env) }
      });
    }
    body = replayStream(sniffed.head, sniffed.reader);
  }

  const headers = new Headers(corsHeaders(request, env));
  headers.set("content-type", contentType || "application/octet-stream");
  headers.set("cache-control", "no-store");
  headers.set("accept-ranges", response.headers.get("accept-ranges") ?? "bytes");
  headers.set("access-control-expose-headers", "content-length,content-range,accept-ranges,etag,last-modified");
  for (const name of ["content-length", "content-range", "etag", "last-modified"]) {
    const value = response.headers.get(name);
    if (value) headers.set(name, value);
  }
  if (wantsDownload) {
    // Content-Disposition makes iOS Safari/Chrome download instead of previewing.
    const rawName = input.searchParams.get("filename") ?? "";
    const safeName = rawName.replace(/[^\w .,()\[\]&'-]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 150) || "arvio-download.mkv";
    headers.set("content-disposition", `attachment; filename="${safeName}"`);
  }
  return new Response(body, { status: response.status, headers });
}
