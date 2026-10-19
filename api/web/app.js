(() => {
  const $ = (s) => document.querySelector(s);
  const B = document.body.dataset;
  const TOKEN = B.t;

  const toast = (t) => {
    const el = $('#toast');
    el.textContent = t;
    el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 1600);
  };
  const say = (t) => {
    const m = $('#m');
    m.textContent = t || '';
    m.hidden = !t;
  };
  const busy = (btn, on) => {
    if (!btn) return;
    btn.disabled = on;
    if (on) btn.setAttribute('aria-busy', 'true');
    else btn.removeAttribute('aria-busy');
  };
  async function post(path, body, token) {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!r.ok) throw new Error('request failed');
    return r.status === 204 ? {} : r.json();
  }
  // Wrap an action: spinner on the button, friendly error, no details.
  const action = (btn, fn) => async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    say('');
    busy(btn, true);
    try {
      await fn();
    } catch (err) {
      say(err && err.name === 'NotAllowedError' ? 'The confirmation was cancelled or timed out. Try again.' : 'That did not work. Check and try again.');
    } finally {
      busy(btn, false);
    }
  };
  const copyText = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      toast('Copied');
    } catch (_) {
      toast('Press Ctrl/Cmd+C to copy');
    }
  };

  document.querySelectorAll('[data-copy]').forEach((b) =>
    b.addEventListener('click', () => copyText($(b.dataset.copy).textContent.trim())));

  const mode = B.mode;

  // ---- second step at sign-in ----
  if (mode === 'mfa') {
    const base = '/auth/mfa';
    const go = (j) => { location.href = j.redirect; };
    // The page only contains the methods this account really has, so every element is optional here.
    const pk = $('#pk');
    if (pk) {
      pk.addEventListener('click', action(pk, async () => {
        const o = await post(base + '/passkey/begin', undefined, TOKEN);
        const a = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(o.publicKey) });
        go(await post(base + '/passkey/finish', a.toJSON(), TOKEN));
      }));
    }
    const submit = (form, input, path) => {
      const btn = form.querySelector('button[type=submit]');
      const run = action(btn, async () => go(await post(base + path, { code: input.value }, TOKEN)));
      form.addEventListener('submit', run);
      return run;
    };
    const totpForm = $('#f-totp');
    if (totpForm) {
      const runTotp = submit(totpForm, $('#totp'), '/totp');
      $('#totp').addEventListener('input', (e) => {
        e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
        if (e.target.value.length === 6) runTotp();
      });
      const tabs = { totp: [$('#tab-totp'), totpForm, $('#totp')], rec: [$('#tab-rec'), $('#f-rec'), $('#rec')] };
      const show = (k) => Object.entries(tabs).forEach(([n, [t, f, i]]) => {
        t.setAttribute('aria-selected', String(n === k));
        f.hidden = n !== k;
        if (n === k) i.focus();
      });
      tabs.totp[0].addEventListener('click', () => show('totp'));
      tabs.rec[0].addEventListener('click', () => show('rec'));
      if (!pk) $('#totp').focus(); // the code is the main way in: ready to type
    }
    submit($('#f-rec'), $('#rec'), '/recovery');
    if (!pk && !totpForm) $('#rec').focus();
  }

  // ---- enrollment ----
  if (mode === 'enroll') {
    const base = '/auth/enroll';
    let redirect = '/auth/done';
    let codes = [];
    const finish = (j) => {
      redirect = j.redirect;
      if (j.recovery_codes && j.recovery_codes.length) {
        codes = j.recovery_codes;
        const ul = $('#codes');
        codes.forEach((c) => {
          const li = document.createElement('li');
          li.textContent = c;
          ul.appendChild(li);
        });
        $('#setup').hidden = true;
        $('#rc').hidden = false;
        $('#ill').hidden = true;
        window.scrollTo(0, 0);
      } else {
        location.href = redirect;
      }
    };
    const pk = $('#pk');
    pk.addEventListener('click', action(pk, async () => {
      const o = await post(base + '/passkey/begin', undefined, TOKEN);
      const c = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(o.publicKey) });
      finish(await post(base + '/passkey/finish', c.toJSON(), TOKEN));
    }));
    const tb = $('#tb');
    tb.addEventListener('click', action(tb, async () => {
      const j = await post(base + '/totp/begin', undefined, TOKEN);
      $('#sec').textContent = j.secret;
      if (j.qr) $('#qr').innerHTML = j.qr; // server-generated SVG of the otpauth URL
      $('#tf').hidden = false;
      $('#setup h1').textContent = 'Set up your authenticator app';
      $('#setup .lead').hidden = true;
      tb.hidden = true;
      pk.hidden = true;
      document.querySelector('.or').hidden = true;
      $('#totp').focus();
    }));
    const tf = $('#tf');
    const confirm = action(tf.querySelector('button[type=submit]'), async () =>
      finish(await post(base + '/totp/confirm', { code: $('#totp').value }, TOKEN)));
    tf.addEventListener('submit', confirm);
    $('#totp').addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
    });
    $('#copy-codes').addEventListener('click', () => copyText(codes.join('\n')));
    $('#dl-codes').addEventListener('click', () => {
      const blob = new Blob(['kuukura recovery codes (each works once)\n\n' + codes.join('\n') + '\n'], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'kuukura-recovery-codes.txt';
      a.click();
      URL.revokeObjectURL(a.href);
    });
    $('#saved').addEventListener('change', (e) => { $('#go').disabled = !e.target.checked; });
    $('#go').addEventListener('click', () => { location.href = redirect; });
  }

  // ---- step-up (Touch ID for a terminal command) ----
  if (mode === 'stepup') {
    const pk = $('#pk');
    pk.addEventListener('click', action(pk, async () => {
      const o = await post('/stepup/' + B.id + '/begin');
      const a = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(o.publicKey) });
      await post('/stepup/' + B.id + '/finish', a.toJSON());
      $('#ask').hidden = true;
      $('#okay').hidden = false;
      const ill = $('#ill');
      ill.innerHTML = document.getElementById('art-done').innerHTML;
    }));
  }
})();
