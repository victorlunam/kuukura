// The landing page's only script: install tabs, copy buttons, and a fallback for browsers without CSS
// scroll-driven animations. It never moves the page and does nothing under reduced motion.

const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ---- tabs (WAI-ARIA tabs pattern, automatic activation) ---- */
for (const root of document.querySelectorAll<HTMLElement>('[data-tabs]')) {
  const tabs = [...root.querySelectorAll<HTMLButtonElement>('[role="tab"]')];
  const select = (tab: HTMLButtonElement, focus: boolean) => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      const panel = document.getElementById(t.getAttribute('aria-controls') ?? '');
      if (panel) panel.hidden = !on;
    }
    if (focus) tab.focus();
  };
  root.addEventListener('click', (e) => {
    const tab = (e.target as Element).closest<HTMLButtonElement>('[role="tab"]');
    if (tab) select(tab, false);
  });
  root.addEventListener('keydown', (e) => {
    const i = tabs.indexOf(document.activeElement as HTMLButtonElement);
    if (i < 0) return;
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const tab = tabs[(next + tabs.length) % tabs.length];
    if (tab) select(tab, true);
  });
}

/* ---- copy ---- */
const live = document.createElement('div');
live.className = 'sr-only';
live.setAttribute('role', 'status');
document.body.append(live);
document.addEventListener('click', async (e) => {
  const btn = (e.target as Element).closest<HTMLButtonElement>('[data-copy]');
  if (!btn) return;
  try {
    await navigator.clipboard.writeText(btn.dataset['copy'] ?? '');
    btn.classList.add('done');
    live.textContent = 'Copied to the clipboard';
    setTimeout(() => {
      btn.classList.remove('done');
      live.textContent = '';
    }, 1600);
  } catch {
    live.textContent = 'Could not copy. Select the command instead.';
  }
});

/* ---- diagram packets run only while the diagram is on screen ---- */
const diagram = document.querySelector<HTMLElement>('.diagram');
if (diagram && !reduced) {
  new IntersectionObserver(([e]) => diagram.classList.toggle('live', !!e?.isIntersecting), {
    threshold: 0.35,
  }).observe(diagram);
}

/* ---- fallback for browsers without scroll-driven animations ---- */
if (!reduced && !CSS.supports('animation-timeline: view()')) {
  document.documentElement.classList.add('fx-io');

  const once = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        e.target.classList.add('is-in');
        once.unobserve(e.target);
      }
    },
    { rootMargin: '0px 0px -12% 0px', threshold: 0.15 },
  );
  for (const el of document.querySelectorAll('[data-reveal], .pl, .answer, .diagram')) once.observe(el);

  const stage = document.querySelector('.stage');
  if (stage) {
    new IntersectionObserver(([e]) => e?.isIntersecting && stage.classList.add('is-in'), {
      rootMargin: '-45% 0px -45% 0px',
    }).observe(stage);
  }

  // The terminal shows every line up to the caption in the middle of the screen, typed one line after another.
  const lines = [...document.querySelectorAll<HTMLElement>('.ln')];
  let shown = 0;
  const show = (step: number) => {
    if (step <= shown) return;
    let delay = 0;
    for (const ln of lines) {
      const s = Number(ln.dataset['s']);
      if (s > shown && s <= step) {
        ln.style.setProperty('--d', `${delay}ms`);
        delay += ln.classList.contains('ln-cmd') ? 260 : 120;
        ln.classList.add('on');
      }
    }
    shown = step;
  };
  const caps = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        e.target.classList.toggle('is-in', e.isIntersecting);
        if (e.isIntersecting) show(Number((e.target as HTMLElement).dataset['step']));
      }
    },
    { rootMargin: '-40% 0px -40% 0px' },
  );
  for (const c of document.querySelectorAll('.cap')) caps.observe(c);
}
