const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { load, storage } = require('./load.cjs');

const diagnostics = load('lib/iptvPlaybackDiagnostics.ts');
const iptv = load('lib/iptv.ts', {
  './storage': storage(),
  './http': { proxiedUrl: (url) => url, textRequest: async () => { throw new Error('Unexpected playlist request'); } }
});
const parse = (...lines) => structuredClone(iptv.parseM3u(lines.join('\n'), 'fixture'));
const httpsPage = { pageProtocol: 'https:', hasRelay: false };

test('a valid M3U keeps channel names, groups and metadata, including Hebrew groups', () => {
  const channels = parse(
    '#EXTM3U x-tvg-url="https://epg.invalid/guide.xml"',
    '#EXTINF:-1 tvg-id="kan11.il" tvg-name="כאן 11" tvg-logo="https://logo.invalid/kan.png" tvg-chno="11" group-title="ישראל",Kan 11 HD',
    'https://media.invalid/live/kan11.m3u8',
    '#EXTINF:-1 group-title="News, World",World News',
    'http://panel.invalid:8080/live/user/pass/42.ts'
  );
  assert.equal(channels.length, 2);
  assert.deepEqual(
    { name: channels[0].name, group: channels[0].group, tvgId: channels[0].tvgId, logo: channels[0].logo, number: channels[0].number, streamUrl: channels[0].streamUrl },
    { name: 'כאן 11', group: 'ישראל', tvgId: 'kan11.il', logo: 'https://logo.invalid/kan.png', number: '11', streamUrl: 'https://media.invalid/live/kan11.m3u8' }
  );
  assert.equal(channels[1].group, 'News, World');
  assert.equal(channels[1].streamUrl, 'http://panel.invalid:8080/live/user/pass/42.ts');
});

test('empty and header-only playlists produce no channels', () => {
  assert.deepEqual(parse(''), []);
  assert.deepEqual(parse('#EXTM3U'), []);
  assert.deepEqual(parse('#EXTM3U', '', '   '), []);
});

test('malformed entries are skipped without dropping the valid channels around them', () => {
  const channels = parse(
    '#EXTM3U',
    'https://orphan.invalid/no-extinf.m3u8',
    '#EXTINF:-1,Missing URL',
    '#EXTINF:-1,Valid after missing URL',
    'https://media.invalid/valid.m3u8',
    '#EXTINF:-1 group-title="Broken quote,Unterminated',
    'https://media.invalid/unterminated.m3u8',
    'not a directive and no pending entry',
    '#EXTINF:-1,Empty URL after pipe',
    '|User-Agent=VLC'
  );
  assert.deepEqual(channels.map((channel) => channel.name), ['Valid after missing URL', 'Unknown Channel']);
});

test('a playlist entry without a usable stream URL is reported as such, not as a network failure', () => {
  for (const missing of [undefined, null, '', '   ', 'not a url', 'live/relative.m3u8', '/absolute-path-only.m3u8']) {
    assert.equal(diagnostics.livePlaybackBlocker(missing, httpsPage), 'invalid-url', String(missing));
  }
  // The parser keeps a relative entry verbatim; diagnostics must not resolve
  // it against the ARVIO origin and pretend it is a provider link.
  const [relative] = parse('#EXTINF:-1,Relative', 'live/relative.m3u8');
  assert.equal(relative.streamUrl, 'live/relative.m3u8');
  assert.equal(diagnostics.livePlaybackBlocker(relative.streamUrl, httpsPage), 'invalid-url');
});

test('schemes a browser cannot play are rejected before the transport is blamed', () => {
  for (const url of ['rtmp://live.invalid/app/stream', 'rtsp://cam.invalid/1', 'udp://@239.0.0.1:1234', 'rtp://239.0.0.1:5004', 'file:///etc/passwd', 'javascript:alert(1)', 'data:video/mp4;base64,AAAA']) {
    assert.equal(diagnostics.livePlaybackBlocker(url, httpsPage), 'unsupported-scheme', url);
  }
  assert.equal(diagnostics.livePlaybackBlocker('https://media.invalid/live.m3u8', httpsPage), null);
});

test('an http channel on an https deployment without a media relay is named as mixed content', () => {
  const url = 'http://panel.invalid:8080/live/user/pass/42.m3u8';
  assert.equal(diagnostics.livePlaybackBlocker(url, httpsPage), 'insecure-without-relay');
  assert.equal(diagnostics.livePlaybackBlocker(url, { pageProtocol: 'https:', hasRelay: true }), null);
  assert.equal(diagnostics.livePlaybackBlocker(url, { pageProtocol: 'http:', hasRelay: false }), null);
  assert.equal(diagnostics.livePlaybackBlocker('HTTP://PANEL.INVALID/live.m3u8', httpsPage), 'insecure-without-relay');
  // Browsers treat loopback as potentially trustworthy, so it is not blocked.
  for (const loopback of ['http://localhost:8080/a.m3u8', 'http://127.0.0.1/a.m3u8', 'http://[::1]:9000/a.m3u8']) {
    assert.equal(diagnostics.isMixedContent('https:', loopback), false, loopback);
  }
  // A LAN tuner is still blocked on an https page.
  assert.equal(diagnostics.isMixedContent('https:', 'http://192.168.1.20:5004/auto/v1'), true);
});

test('stream summaries identify the format through redirects and encodings without exposing the URL', () => {
  const cases = [
    ['https://cdn.invalid/live/index.m3u8?token=secret', 'hls'],
    ['https://cdn.invalid/live/index%2Em3u8', 'hls'],
    ['http://panel.invalid/get.php?username=u&password=p&output=m3u8', 'hls'],
    ['http://panel.invalid/live/u/p/42.ts', 'mpegts'],
    ['http://panel.invalid/play?output=ts', 'mpegts'],
    ['https://cdn.invalid/manifest.mpd', 'dash'],
    ['https://cdn.invalid/movie.mp4', 'file'],
    ['http://panel.invalid/live/u/p/42', 'unknown']
  ];
  for (const [url, kind] of cases) {
    const summary = diagnostics.summarizeStreamUrl(url);
    assert.equal(summary.kind, kind, url);
    const serialized = JSON.stringify(summary);
    for (const secret of ['secret', 'panel.invalid', 'cdn.invalid', 'username', 'password', '/live/']) assert.ok(!serialized.includes(secret), `${url} leaked ${secret}`);
  }
  assert.deepEqual(structuredClone(diagnostics.summarizeStreamUrl('nonsense')), { scheme: 'invalid', kind: 'unknown' });
});

test('ladder attempts are labelled by route only', () => {
  const app = 'https://arvio.example';
  const relay = 'https://relay.example';
  assert.equal(diagnostics.playbackAttemptRoute('http://panel.invalid/live/u/p/1.m3u8', app, relay), 'direct');
  assert.equal(diagnostics.playbackAttemptRoute(`${relay}/media?url=http%3A%2F%2Fpanel.invalid%2F1.m3u8`, app, relay), 'relay');
  assert.equal(diagnostics.playbackAttemptRoute(`${app}/api/proxy?url=x&rewrite=direct`, app, relay), 'app-proxy:direct');
  assert.equal(diagnostics.playbackAttemptRoute(`${app}/api/proxy?url=x`, app, ''), 'app-proxy:media');
  // Without a configured relay, nothing is mistaken for one.
  assert.equal(diagnostics.playbackAttemptRoute(`${relay}/media?url=x`, app, ''), 'direct');
});

test('console diagnostics cannot carry URLs, credentials or query strings', () => {
  const line = diagnostics.playbackDiagnosticLine('attempt-failed', {
    scheme: 'http', kind: 'hls', code: 'manifestLoadError', media_error: 4, skipped: undefined,
    leaked: 'http://user:pass@panel.invalid/live/u/p/1.m3u8?token=abc'
  });
  assert.match(line, /^\[ARVIO IPTV\] attempt-failed scheme=http kind=hls code=manifestLoadError media_error=4 leaked=/);
  for (const fragment of ['/', '?', '@', '=abc', 'token=']) assert.ok(!line.slice(line.indexOf('leaked=') + 7).includes(fragment), fragment);
  assert.ok(!line.includes('skipped'));
});

test('every live playback blocker has a Hebrew explanation in the shipped dictionary', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../components/player/PlayerOverlay.tsx'), 'utf8');
  const block = source.slice(source.indexOf('{liveBlocker &&'), source.indexOf('</small>}', source.indexOf('{liveBlocker &&')));
  const messages = [...block.matchAll(/translateUi\("([^"]+)"\)/g)].map((match) => match[1]);
  assert.equal(messages.length, 3);
  for (const blocker of ['insecure-without-relay', 'unsupported-scheme']) assert.ok(block.includes(`"${blocker}"`), blocker);
  const he = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../public/i18n/he.json'), 'utf8'));
  for (const message of messages) {
    assert.ok(he[message], message);
    assert.match(he[message], /[֐-׿]/, `${message} is not translated to Hebrew`);
  }
});
