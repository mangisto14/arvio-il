import test from "node:test";
import assert from "node:assert/strict";
import { relay, worker } from "./load.mjs";

// Fixtures use reserved names (RFC 2606/6761) and documentation addresses
// (RFC 5737). "subscriber"/"s3cr3t" are dummy credentials used to prove they
// never appear in error output.
const APP = "https://arvio.example";
const KEY = "test-signing-key-0123456789abcdef-0123456789";
const ENV = { ALLOWED_ORIGINS: APP, MEDIA_ALLOWED_HOSTS: "panel.example,*.cdn.example", MEDIA_SIGNING_KEY: KEY };
const NOW = Date.UTC(2026, 9, 12, 12, 0, 0);
const now = () => NOW;
const SECRET = "s3cr3t";
const LIVE = `http://panel.example:8080/live/subscriber/${SECRET}/42.m3u8?token=a%2Fb+c&x=1`;

function upstream(routes) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, method: init.method, headers: Object.fromEntries(new Headers(init.headers)), redirect: init.redirect });
    const route = routes[url];
    if (!route) return new Response("not found", { status: 404 });
    return typeof route === "function" ? route(url, init) : route.clone();
  };
  return { fetchImpl, calls };
}

const relayUrl = (target, extra = {}) => {
  const url = new URL("https://relay.example/media");
  url.searchParams.set("url", target);
  for (const [key, value] of Object.entries(extra)) url.searchParams.set(key, value);
  return url.toString();
};
const get = (url, headers = {}, method = "GET") => new Request(url.startsWith("/") ? `https://relay.example${url}` : url, { method, headers });
const call = (request, routes, env = ENV) => {
  const fake = upstream(routes);
  return relay.handleMedia(request, env, fake.fetchImpl, now).then((response) => ({ response, calls: fake.calls }));
};
const playlist = (body, type = "application/vnd.apple.mpegurl") => new Response(body, { status: 200, headers: { "content-type": type } });
async function assertSafeError(response, status) {
  assert.equal(response.status, status);
  const text = await response.text();
  for (const leak of [SECRET, "subscriber", "panel.example", "token="]) assert.ok(!text.includes(leak), `error leaked ${leak}: ${text}`);
}

test("fails closed until origins, allowed hosts and a strong signing key are configured", async () => {
  for (const env of [{ ...ENV, ALLOWED_ORIGINS: "" }, { ...ENV, MEDIA_ALLOWED_HOSTS: " " }, { ...ENV, MEDIA_SIGNING_KEY: "short" }, {}]) {
    const { response, calls } = await call(get(relayUrl(LIVE)), { [LIVE]: playlist("#EXTM3U\n") }, env);
    await assertSafeError(response, 503);
    assert.equal(calls.length, 0);
  }
});

test("unsigned requests may only reach allowlisted hosts; wildcards cover subdomains only", async () => {
  for (const target of ["https://evil.example/a.m3u8", "https://cdn.example/a.ts", "https://evilcdn.example/a.ts", "https://panel.example.evil.example/a.ts"]) {
    const { response, calls } = await call(get(relayUrl(target)), {});
    await assertSafeError(response, 403);
    assert.equal(calls.length, 0, target);
  }
  assert.equal(relay.hostAllowed("edge1.cdn.example", ENV.MEDIA_ALLOWED_HOSTS), true);
  assert.equal(relay.hostAllowed("PANEL.EXAMPLE.", ENV.MEDIA_ALLOWED_HOSTS), true);
});

test("Origin is enforced when present, while native Safari/VLC requests (no Origin) still work", async () => {
  const routes = { "https://panel.example/v.ts": new Response("video", { headers: { "content-type": "video/mp2t" } }) };
  let { response, calls } = await call(get(relayUrl("https://panel.example/v.ts"), { origin: "https://attacker.example" }), routes);
  await assertSafeError(response, 403);
  assert.equal(calls.length, 0);
  ({ response } = await call(get(relayUrl("https://panel.example/v.ts"), { origin: APP }), routes));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("access-control-allow-origin"), APP);
  ({ response } = await call(get(relayUrl("https://panel.example/v.ts")), routes));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "video");
});

test("CORS never falls back to a wildcard", () => {
  const headers = relay.corsHeaders(new Request("https://relay.example/x", { headers: { origin: APP } }), { ALLOWED_ORIGINS: "" });
  assert.equal(headers["access-control-allow-origin"], undefined);
  const other = relay.corsHeaders(new Request("https://relay.example/x", { headers: { origin: "https://attacker.example" } }), ENV);
  assert.equal(other["access-control-allow-origin"], APP);
});

test("loopback, private, link-local, metadata and mapped addresses are refused even if allowlisted", async () => {
  const env = { ...ENV, MEDIA_ALLOWED_HOSTS: "localhost,127.0.0.1,10.0.0.5,192.168.1.1,169.254.169.254,[::1],a.localhost,router.local" };
  for (const target of ["http://localhost/a", "http://127.0.0.1/a", "http://2130706433/a", "http://0x7f.1/a", "http://10.0.0.5/a", "http://192.168.1.1:8080/a",
    "http://169.254.169.254/latest/meta-data", "http://[::1]/a", "http://[::ffff:127.0.0.1]/a", "http://[fd00::1]/a", "http://a.localhost/a", "http://router.local/a",
    "http://100.64.0.1/a", "http://172.16.0.1/a", "http://0.0.0.0/a", "http://224.0.0.1/a"]) {
    const { response, calls } = await call(get(relayUrl(target)), {}, env);
    assert.equal(response.status, 403, target);
    assert.equal(calls.length, 0, target);
  }
  assert.equal(relay.blockedHost("203.0.113.10"), false);
  assert.equal(relay.blockedHost("panel.example"), false);
});

test("non-http schemes and URL-embedded credentials are refused", async () => {
  for (const target of ["ftp://panel.example/a", "file:///etc/passwd", "rtmp://panel.example/live", `http://subscriber:${SECRET}@panel.example/a.m3u8`, "not a url"]) {
    const { response, calls } = await call(get(relayUrl(target)), {});
    assert.ok([400, 403].includes(response.status), target);
    await assertSafeError(response, response.status);
    assert.equal(calls.length, 0);
  }
});

const MASTER = [
  "#EXTM3U",
  '#EXT-X-SESSION-KEY:METHOD=SAMPLE-AES,URI="skd://fairplay-key",KEYFORMAT="com.apple.streamingkeydelivery"',
  '#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="aud",NAME="עברית",URI="audio/he.m3u8"',
  '#EXT-X-STREAM-INF:BANDWIDTH=800000,AUDIO="aud"',
  "low/index.m3u8",
  "#EXT-X-STREAM-INF:BANDWIDTH=2000000",
  "http://203.0.113.10:25461/hi/index.m3u8?sig=edge%2Btoken&n=1"
].join("\n");
const MEDIA = [
  "#EXTM3U",
  "#EXT-X-TARGETDURATION:4",
  '#EXT-X-KEY:METHOD=AES-128,URI="../keys/k1.key?t=1",IV=0x1',
  '#EXT-X-MAP:URI="init.mp4"',
  "#EXTINF:4,",
  "seg-1.ts?part=a+b%26c",
  "#EXTINF:4,",
  "/abs/seg-2.ts",
  '#EXT-X-PART:DURATION=1,URI="data:video/mp2t;base64,AAAA"'
].join("\r\n");

function relayedTargets(text) {
  return [...text.matchAll(/\/media\?[^"\s]+/g)].map((match) => new URLSearchParams(match[0].slice("/media?".length)));
}

test("playlists are rewritten after redirects: relative, absolute, URI attributes, keys and init sections are signed", async () => {
  const final = "http://edge.cdn.example/live/subscriber/s3cr3t/42/master.m3u8";
  const routes = {
    [LIVE]: new Response(null, { status: 302, headers: { location: final } }),
    [final]: playlist(MASTER)
  };
  const { response, calls } = await call(get(relayUrl(LIVE, { h: btoa(JSON.stringify({ "User-Agent": "TiviMate/5" })) })), routes);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/vnd.apple.mpegurl");
  assert.equal(calls[0].redirect, "manual");
  const text = await response.text();
  assert.match(text, /URI="skd:\/\/fairplay-key"/);
  const targets = relayedTargets(text).map((params) => params.get("url"));
  assert.deepEqual(targets, [
    "http://edge.cdn.example/live/subscriber/s3cr3t/42/audio/he.m3u8",
    "http://edge.cdn.example/live/subscriber/s3cr3t/42/low/index.m3u8",
    "http://203.0.113.10:25461/hi/index.m3u8?sig=edge%2Btoken&n=1"
  ]);
  for (const params of relayedTargets(text)) {
    assert.equal(params.get("exp"), String(Math.floor(NOW / 1000) + 43200));
    assert.equal(params.get("h"), btoa(JSON.stringify({ "User-Agent": "TiviMate/5" })));
    assert.match(params.get("sig"), /^[\w-]{43}$/);
  }
});

test("signed child links work for non-allowlisted hosts (edge IPs) and reproduce the exact URL, query included", async () => {
  const master = "https://panel.example/m.m3u8";
  const media = "http://203.0.113.10:25461/hi/index.m3u8?sig=edge%2Btoken&n=1";
  const keyUrl = "http://203.0.113.10:25461/keys/k1.key?t=1";
  const segment = "http://203.0.113.10:25461/hi/seg-1.ts?part=a+b%26c";
  const routes = {
    [master]: playlist(MASTER),
    [media]: playlist(MEDIA, "text/plain"),
    [keyUrl]: new Response(new Uint8Array(16).fill(7), { headers: { "content-type": "application/octet-stream" } }),
    [segment]: new Response("TS-BYTES", { headers: { "content-type": "video/mp2t" } })
  };
  const first = await (await call(get(relayUrl(master)), routes)).response.text();
  const variant = relayedTargets(first)[2];
  const second = await call(get(`/media?${variant}`), routes);
  assert.equal(second.calls[0].url, media);
  const mediaText = await second.response.text();
  const children = relayedTargets(mediaText);
  assert.deepEqual(children.map((params) => params.get("url")), [
    keyUrl, "http://203.0.113.10:25461/hi/init.mp4", segment, "http://203.0.113.10:25461/abs/seg-2.ts"
  ]);
  assert.match(mediaText, /URI="data:video\/mp2t;base64,AAAA"/);
  const key = await call(get(`/media?${children[0]}`), routes);
  assert.equal(key.response.status, 200);
  assert.deepEqual(new Uint8Array(await key.response.arrayBuffer()), new Uint8Array(16).fill(7));
  const seg = await call(get(`/media?${children[2]}`), routes);
  assert.equal(seg.calls[0].url, segment);
  assert.equal(await seg.response.text(), "TS-BYTES");
});

test("tampered, expired, over-long or download-scoped signatures are refused", async () => {
  const target = "http://203.0.113.10/hi/seg.ts";
  const exp = Math.floor(NOW / 1000) + 600;
  const sig = await relay.signMediaUrl(KEY, target, "", exp);
  const cases = [
    { url: "http://203.0.113.11/hi/seg.ts", exp, sig },
    { url: target, exp: exp + 1, sig },
    { url: target, exp, sig, h: btoa(JSON.stringify({ Cookie: "x" })) },
    { url: target, exp: Math.floor(NOW / 1000) - 1, sig: await relay.signMediaUrl(KEY, target, "", Math.floor(NOW / 1000) - 1) },
    { url: target, exp: Math.floor(NOW / 1000) + 30 * 24 * 3600, sig: await relay.signMediaUrl(KEY, target, "", Math.floor(NOW / 1000) + 30 * 24 * 3600) },
    { url: target, exp, sig: "A".repeat(43) },
    { url: target, exp, sig: "not-base64!" },
    { url: target, exp, sig: await relay.signMediaUrl("another-signing-key-0123456789abcdef-0123", target, "", exp) },
    { url: target, exp, sig, dl: "1" }
  ];
  for (const params of cases) {
    const { response, calls } = await call(get(`/media?${new URLSearchParams(Object.fromEntries(Object.entries(params).map(([k, v]) => [k, String(v)])))}`), { [target]: new Response("x") });
    await assertSafeError(response, 403);
    assert.equal(calls.length, 0, JSON.stringify(params));
  }
  const ok = await call(get(`/media?${new URLSearchParams({ url: target, exp: String(exp), sig })}`), { [target]: new Response("x", { headers: { "content-type": "video/mp2t" } }) });
  assert.equal(ok.response.status, 200);
});

test("playlists are detected by content, not only by extension or content type", async () => {
  for (const type of ["text/plain", "application/octet-stream", "", "application/x-mpegurl; charset=utf-8"]) {
    const target = "https://panel.example/live/subscriber/s3cr3t/42";
    const { response } = await call(get(relayUrl(target)), { [target]: new Response("\uFEFF  #EXTM3U\n#EXTINF:4,\nseg.ts\n", { headers: type ? { "content-type": type } : {} }) });
    assert.equal(response.headers.get("content-type"), "application/vnd.apple.mpegurl", type);
    assert.match(await response.text(), /\/media\?url=https%3A%2F%2Fpanel\.example%2Flive%2Fsubscriber%2Fs3cr3t%2Fseg\.ts/);
  }
});

test("binary media is streamed byte-for-byte, including when sniffed as a possible playlist", async () => {
  const bytes = new Uint8Array(70_000).map((_, index) => (index * 31) % 256);
  for (const type of ["video/mp2t", "application/octet-stream", "video/iso.segment"]) {
    const target = "https://panel.example/seg.ts";
    const { response } = await call(get(relayUrl(target)), { [target]: new Response(bytes, { headers: { "content-type": type, "content-length": String(bytes.length) } }) });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-length"), String(bytes.length));
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes, type);
  }
});

test("oversized playlists are refused", async () => {
  const target = "https://panel.example/huge.m3u8";
  const huge = "#EXTM3U\n" + "#EXTINF:4,\nseg.ts\n".repeat(300_000);
  const { response } = await call(get(relayUrl(target)), { [target]: playlist(huge) });
  await assertSafeError(response, 502);
});

test("redirects are followed manually, re-validated per hop, bounded, and drop credentials across origins", async () => {
  const headers = btoa(JSON.stringify({ Authorization: "Bearer dummy", Cookie: "session=dummy", Referer: "https://panel.example/", "X-Forwarded-For": "1.2.3.4" }));
  const start = "https://panel.example/a.ts";
  let result = await call(get(relayUrl(start, { h: headers })), {
    [start]: new Response(null, { status: 302, headers: { location: "/b.ts" } }),
    "https://panel.example/b.ts": new Response(null, { status: 307, headers: { location: "http://203.0.113.10:8080/c.ts" } }),
    "http://203.0.113.10:8080/c.ts": new Response("ok", { headers: { "content-type": "video/mp2t" } })
  });
  assert.equal(result.response.status, 200);
  assert.deepEqual(result.calls.map((entry) => entry.url), [start, "https://panel.example/b.ts", "http://203.0.113.10:8080/c.ts"]);
  assert.equal(result.calls[1].headers.authorization, "Bearer dummy");
  assert.equal(result.calls[2].headers.authorization, undefined);
  assert.equal(result.calls[2].headers.cookie, undefined);
  assert.equal(result.calls[2].headers.referer, "https://panel.example/");
  assert.equal(result.calls[0].headers["x-forwarded-for"], undefined);

  result = await call(get(relayUrl(start)), { [start]: new Response(null, { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data" } }) });
  await assertSafeError(result.response, 403);
  assert.equal(result.calls.length, 1);

  const loop = {};
  for (let index = 0; index < 8; index++) loop[`https://panel.example/r${index}`] = new Response(null, { status: 302, headers: { location: `/r${index + 1}` } });
  result = await call(get(relayUrl("https://panel.example/r0")), loop);
  await assertSafeError(result.response, 502);
  assert.equal(result.calls.length, 6);
});

test("range requests and HEAD pass through without playlist sniffing", async () => {
  const target = "https://panel.example/movie.mp4";
  const fake = upstream({
    [target]: (_url, init) => new Response(init.method === "HEAD" ? null : "PARTIAL", {
      status: 206, headers: { "content-type": "video/mp4", "content-range": "bytes 100-106/5000", "content-length": "7", "accept-ranges": "bytes" }
    })
  });
  let response = await relay.handleMedia(get(relayUrl(target), { range: "bytes=100-106" }), ENV, fake.fetchImpl, now);
  assert.equal(response.status, 206);
  assert.equal(fake.calls[0].headers.range, "bytes=100-106");
  assert.equal(response.headers.get("content-range"), "bytes 100-106/5000");
  assert.equal(response.headers.get("content-length"), "7");
  assert.equal(await response.text(), "PARTIAL");
  response = await relay.handleMedia(get(relayUrl(target), {}, "HEAD"), ENV, fake.fetchImpl, now);
  assert.equal(fake.calls[1].method, "HEAD");
  assert.equal(response.body, null);
});

test("a byte-range probe on a playlist (Safari/Chromium <video>) still returns the whole rewritten playlist", async () => {
  const target = "http://panel.example:8080/live/subscriber/s3cr3t/77";
  const body = "#EXTM3U\n#EXTINF:4,\nseg.ts\n";
  const fake = upstream({
    [target]: (_url, init) => {
      const range = new Headers(init.headers).get("range");
      if (!range) return new Response(body, { headers: { "content-type": "text/plain" } });
      return new Response(body.slice(0, 2), { status: 206, headers: { "content-type": "text/plain", "content-range": `bytes 0-1/${body.length}` } });
    }
  });
  const response = await relay.handleMedia(get(relayUrl(target), { range: "bytes=0-1" }), ENV, fake.fetchImpl, now);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/vnd.apple.mpegurl");
  assert.match(await response.text(), /^\/media\?url=http%3A%2F%2Fpanel\.example%3A8080%2Flive%2Fsubscriber%2Fs3cr3t%2Fseg\.ts&exp=\d+&sig=[\w-]{43}$/m);
  assert.deepEqual(fake.calls.map((entry) => entry.headers.range), ["bytes=0-1", undefined]);
  // Video ranges are never refetched whole.
  const video = "https://panel.example/v.ts";
  const second = upstream({ [video]: new Response("ab", { status: 206, headers: { "content-type": "video/mp2t", "content-range": "bytes 0-1/100" } }) });
  const partial = await relay.handleMedia(get(relayUrl(video), { range: "bytes=0-1" }), ENV, second.fetchImpl, now);
  assert.equal(partial.status, 206);
  assert.equal(second.calls.length, 1);
});

test("a custom port silently replaced by Cloudflare's proxy is detected instead of served", async () => {
  const proxied = "http://panel.example:25461/live/a.ts";
  let { response } = await call(get(relayUrl(proxied)), { [proxied]: new Response("wrong service", { headers: { "cf-ray": "abc", "content-type": "text/html" } }) });
  await assertSafeError(response, 502);
  for (const ok of ["http://panel.example:8080/live/a.ts", "http://panel.example:25461/live/b.ts"]) {
    ({ response } = await call(get(relayUrl(ok)), { [ok]: new Response("ts", { headers: ok.includes(":8080") ? { "cf-ray": "abc", "content-type": "video/mp2t" } : { "content-type": "video/mp2t" } }) }));
    assert.equal(response.status, 200, ok);
  }
});

test("upstream failures return generic errors without the target URL", async () => {
  const { response } = await call(get(relayUrl(LIVE)), { [LIVE]: () => { throw new TypeError(`connect failed ${LIVE}`); } });
  await assertSafeError(response, 502);
});

test("downloads from an allowlisted host keep Content-Disposition with a sanitized filename", async () => {
  const target = "https://dl.cdn.example/file.mkv";
  const { response } = await call(get(relayUrl(target, { dl: "1", filename: 'Movie "2026"/<script>.mkv' })), { [target]: new Response("MKV", { headers: { "content-type": "video/x-matroska" } }) });
  assert.equal(response.headers.get("content-disposition"), 'attachment; filename="Movie 2026 script .mkv"');
});

// Worker routes outside /media.
async function withFetch(fake, run) {
  const original = globalThis.fetch;
  const originalCaches = globalThis.caches;
  globalThis.fetch = fake;
  // Workers' edge cache global; a miss-only stand-in is enough here.
  globalThis.caches = { default: { match: async () => undefined, put: async () => undefined } };
  try { return await run(); } finally { globalThis.fetch = original; globalThis.caches = originalCaches; }
}

test("/api/tmdb is disabled by TMDB_EDGE_CACHE=off and never reaches the upstream fallback", async () => {
  let fetched = 0;
  const response = await withFetch(async () => { fetched++; return new Response("{}"); },
    () => worker.fetch(new Request("https://relay.example/api/tmdb/movie/1"), { ...ENV, TMDB_EDGE_CACHE: "off" }));
  assert.equal(response.status, 404);
  assert.equal(fetched, 0);
});

test("/subtitle enforces Origin, refuses private targets, bounds size and still converts SRT", async () => {
  const srt = "1\n00:00:01,000 --> 00:00:02,000\nשלום\n";
  let response = await withFetch(async () => new Response(srt), () => worker.fetch(new Request(`https://relay.example/subtitle?url=${encodeURIComponent("https://subs.example/a.srt")}`, { headers: { origin: "https://attacker.example" } }), ENV));
  assert.equal(response.status, 403);
  response = await withFetch(async () => new Response(srt), () => worker.fetch(new Request(`https://relay.example/subtitle?url=${encodeURIComponent("http://169.254.169.254/x")}`), ENV));
  assert.equal(response.status, 403);
  response = await withFetch(async () => new Response("x".repeat(6 * 1024 * 1024)), () => worker.fetch(new Request(`https://relay.example/subtitle?url=${encodeURIComponent("https://subs.example/big.srt")}`), ENV));
  assert.equal(response.status, 502);
  response = await withFetch(async () => new Response(srt), () => worker.fetch(new Request(`https://relay.example/subtitle?url=${encodeURIComponent("https://subs.example/a.srt")}`, { headers: { origin: APP } }), ENV));
  assert.equal(response.status, 200);
  assert.match(await response.text(), /^WEBVTT[\s\S]*00:00:01\.000 --> 00:00:02\.000\nשלום/);
});

test("/proxy (debrid and catalog APIs) is unchanged: TorBox requests keep their bearer token", async () => {
  const seen = [];
  const h = btoa(JSON.stringify({ Authorization: "Bearer dummy-torbox-key" }));
  const response = await withFetch(async (url, init) => { seen.push({ url: String(url), auth: new Headers(init.headers).get("authorization") }); return new Response('{"success":true}', { headers: { "content-type": "application/json" } }); },
    () => worker.fetch(new Request(`https://relay.example/proxy?url=${encodeURIComponent("https://api.torbox.app/v1/api/user/me")}&h=${encodeURIComponent(h)}`, { headers: { origin: APP } }), ENV));
  assert.equal(response.status, 200);
  assert.deepEqual(seen, [{ url: "https://api.torbox.app/v1/api/user/me", auth: "Bearer dummy-torbox-key" }]);
  const blocked = await worker.fetch(new Request(`https://relay.example/proxy?url=${encodeURIComponent("https://evil.example/x")}`), ENV);
  assert.equal(blocked.status, 400);
});
