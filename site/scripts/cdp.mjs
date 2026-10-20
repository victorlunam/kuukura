// A tiny Chrome DevTools Protocol client for headless screenshots. No dependencies: Node 22+ has fetch and WebSocket.
// Used by scripts/screens.mjs (product screenshots) and for local review shots of the site.
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CHROME =
  process.env.CHROME ??
  (process.platform === 'darwin'
    ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    : 'google-chrome');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function launch() {
  const profile = await mkdtemp(join(tmpdir(), 'ku-cdp-'));
  const proc = spawn(
    CHROME,
    [
      '--headless=new',
      '--remote-debugging-port=0',
      `--user-data-dir=${profile}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--hide-scrollbars',
      '--force-color-profile=srgb',
      'about:blank',
    ],
    { stdio: 'ignore' },
  );
  let port;
  for (let i = 0; i < 100 && !port; i++) {
    await sleep(100);
    try {
      port = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0];
    } catch {
      /* not yet */
    }
  }
  if (!port) throw new Error('Chrome did not start');
  const { webSocketDebuggerUrl } = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  const ws = new WebSocket(webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.onopen = res;
    ws.onerror = rej;
  });
  let id = 0;
  const pending = new Map();
  const listeners = new Set();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { res, rej } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) rej(new Error(msg.error.message));
      else res(msg.result);
    } else if (msg.method) {
      for (const l of listeners) l(msg);
    }
  };
  const send = (method, params = {}, sessionId) =>
    new Promise((res, rej) => {
      const n = ++id;
      pending.set(n, { res, rej });
      ws.send(JSON.stringify({ id: n, method, params, sessionId }));
    });

  async function page() {
    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    const s = (m, p) => send(m, p, sessionId);
    await s('Page.enable');
    const waitLoad = () =>
      new Promise((res) => {
        const l = (msg) => {
          if (msg.sessionId === sessionId && msg.method === 'Page.loadEventFired') {
            listeners.delete(l);
            res();
          }
        };
        listeners.add(l);
      });
    return {
      send: s,
      async viewport(width, height, { dark = true, reducedMotion = false, scale = 2 } = {}) {
        await s('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: scale, mobile: width < 600 });
        await s('Emulation.setEmulatedMedia', {
          features: [
            { name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' },
            { name: 'prefers-reduced-motion', value: reducedMotion ? 'reduce' : 'no-preference' },
          ],
        });
      },
      async goto(url) {
        const loaded = waitLoad();
        await s('Page.navigate', { url });
        await loaded;
        await sleep(400);
      },
      async eval(expression) {
        const r = await s('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
        return r.result?.value;
      },
      async shot({ full = false } = {}) {
        let clip;
        if (full) {
          const m = await s('Page.getLayoutMetrics');
          clip = { x: 0, y: 0, width: m.cssContentSize.width, height: m.cssContentSize.height, scale: 1 };
        }
        const { data } = await s('Page.captureScreenshot', { format: 'png', captureBeyondViewport: full, clip });
        return Buffer.from(data, 'base64');
      },
      close: () => send('Target.closeTarget', { targetId }),
    };
  }

  return {
    page,
    async close() {
      try {
        await send('Browser.close');
      } catch {
        /* already gone */
      }
      const exited = new Promise((r) => proc.once('exit', r));
      proc.kill();
      await Promise.race([exited, sleep(3000)]);
      await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    },
  };
}

export { sleep };
