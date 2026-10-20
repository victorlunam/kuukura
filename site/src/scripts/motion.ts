// The only motion script (see styles/motion.css). It never moves the page and does nothing under reduced motion.
// 1. Runs the diagram's packets only while the diagram is on screen.
// 2. Where CSS scroll-driven animations are missing, marks <html data-motion="io"> and sets data-in on what has
//    scrolled into view, so the CSS can transition instead.

const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

if (!reduced) {
  for (const root of document.querySelectorAll<HTMLElement>('[data-draw-root]')) {
    new IntersectionObserver(([e]) => root.toggleAttribute('data-live', !!e?.isIntersecting), { threshold: 0.35 }).observe(
      root,
    );
  }
}

if (!reduced && !CSS.supports('animation-timeline: view()')) {
  document.documentElement.dataset['motion'] = 'io';
  const mark = (el: Element) => el.setAttribute('data-in', '');

  const once = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        mark(e.target);
        once.unobserve(e.target);
      }
    },
    { rootMargin: '0px 0px -12% 0px', threshold: 0.15 },
  );
  for (const el of document.querySelectorAll('[data-reveal], [data-dim], [data-draw-root]')) once.observe(el);

  const middle = { rootMargin: '-45% 0px -45% 0px' };
  for (const stage of document.querySelectorAll('[data-stage]')) {
    new IntersectionObserver(([e]) => e?.isIntersecting && mark(stage), middle).observe(stage);
  }

  // Terminal lines appear up to the caption in the middle of the screen, one after another.
  for (const scene of document.querySelectorAll('[data-steps]')) {
    const lines = [...scene.querySelectorAll<HTMLElement>('[data-line]')];
    let shown = 0;
    const show = (step: number) => {
      if (step <= shown) return;
      let delay = 0;
      for (const ln of lines) {
        const s = Number(ln.dataset['step']);
        if (s <= shown || s > step) continue;
        ln.style.setProperty('--d', `${delay}ms`);
        delay += ln.hasAttribute('data-command') ? 260 : 120;
        mark(ln);
      }
      shown = step;
    };
    const captions = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          e.target.toggleAttribute('data-in', e.isIntersecting);
          if (e.isIntersecting) show(Number((e.target as HTMLElement).dataset['stepCaption']));
        }
      },
      { rootMargin: '-40% 0px -40% 0px' },
    );
    for (const c of scene.querySelectorAll('[data-step-caption]')) captions.observe(c);
  }
}
