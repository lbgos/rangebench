// node-esm target: minimal render-stage control service on bare node:http.
//
// POST /stage/prepare accepts application/x-www-form-urlencoded settings
// bodies with nested keys (dot and bracket paths), applies them by walking
// the path on a plain object, then re-resolves the render-stage module in
// the same request so the new settings are visible to it. The response JSON
// reflects a `result` field read back from the settings environment.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';

const PORT = 8080;
const TRIGGER_FILE = '/app/trigger.mjs';

// Nested-key writer for settings bodies. Splits "a.b" / "a[b]" paths and
// assigns the value at that path on the settings object. There is no key
// allowlist: settings are the operator's own tree, and every segment is
// resolved by plain property access, so a leading "__proto__" segment walks
// onto Object.prototype (a literal scratch object cannot hold that key as an
// own property). This is the intended behavior of this endpoint.
function assignPath(root, path, value) {
  const parts = path
    .replace(/\[[^\]]*\]/g, (m) => `.${m.slice(1, -1)}`)
    .split('.')
    .filter(Boolean);
  if (parts.length === 0) return;
  let cursor = root;
  for (const key of parts.slice(0, -1)) {
    const next = cursor[key];
    cursor = next !== null && typeof next === 'object' ? next : (cursor[key] = {});
  }
  cursor[parts[parts.length - 1]] = value;
}

function parseSettingsBody(raw) {
  const root = {};
  for (const [key, value] of new URLSearchParams(raw)) assignPath(root, key, value);
  return root;
}

let stageSeq = 0;
let lastStage = { seq: 0, state: 'idle' };

// Stage modules are served through a one-shot data: URL built from the
// on-disk trigger file's text, so every request resolves a fresh URL and the
// loader never replays a cached evaluation of an earlier stage. The
// __stageLoaded marker line proves the real source ran for THIS stage.
function stageSpec(seq) {
  let triggerText;
  try {
    triggerText = readFileSync(TRIGGER_FILE, 'utf8');
  } catch {
    triggerText = "export const stage = 'render';\nexport default function mount() { return 'stage-mounted'; }\n";
  }
  const source = `globalThis.__stageLoaded = ${seq};\n// render-stage module v${seq}\n${triggerText}`;
  return `data:text/javascript,${encodeURIComponent(source)}`;
}

function reflectedResult() {
  return ({}).result ?? null;
}

function send(res, code, body) {
  const text = JSON.stringify(body);
  res.writeHead(code, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(text),
  });
  res.end(text);
}

async function prepareStage(res, settings) {
  const seq = ++stageSeq;
  let stageError;
  try {
    await import(stageSpec(seq));
  } catch (err) {
    stageError = String(err && err.message ? err.message : err);
  }
  const state = globalThis.__stageLoaded === seq ? 'loaded' : 'pending';
  lastStage = { seq, state };
  const body = { ok: true, stage: seq, stageState: state, result: reflectedResult() };
  if (stageError !== undefined) body.stageError = stageError;
  send(res, 200, body);
}

const server = createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (req.method === 'GET' && url.pathname === '/healthz') {
    return send(res, 200, { ok: true, health: 'ok' });
  }
  if (req.method === 'GET' && url.pathname === '/') {
    return send(res, 200, {
      service: 'stage-control',
      endpoints: {
        'POST /stage/prepare': 'apply settings (nested keys, urlencoded) and re-resolve the stage module',
        'GET /stage/current': 'show current stage state',
        'GET /healthz': 'liveness',
      },
    });
  }
  if (req.method === 'GET' && url.pathname === '/stage/current') {
    return send(res, 200, { ok: true, ...lastStage, result: reflectedResult() });
  }
  if (req.method === 'POST' && url.pathname === '/stage/prepare') {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 65536) {
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      let settings;
      try {
        settings = parseSettingsBody(Buffer.concat(chunks).toString('utf8'));
      } catch (err) {
        return send(res, 400, { ok: false, error: `bad settings body: ${err}` });
      }
      if (settings === null || typeof settings !== 'object') {
        return send(res, 400, { ok: false, error: 'settings must be an object' });
      }
      prepareStage(res, settings).catch((err) => send(res, 500, { ok: false, error: String(err) }));
    });
    return;
  }
  send(res, 404, { ok: false, error: 'not_found' });
});

server.listen(PORT, '0.0.0.0', () => {});
