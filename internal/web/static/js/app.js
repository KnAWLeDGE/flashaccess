/* FlashAccess — app.js */

/* ── Session countdown timer ─────────────────────────────── */
(function () {
  var el = document.getElementById('js-timer');
  if (!el) return;

  var expires = parseInt(el.dataset.expires, 10); // Unix seconds

  function update() {
    var remaining = expires - Math.floor(Date.now() / 1000);
    if (remaining <= 0) {
      el.textContent = '00:00:00';
      el.style.color = 'var(--err-text)';
      // Reload so the server redirects to /setup
      setTimeout(function () { window.location.href = '/setup'; }, 800);
      return;
    }

    var h = Math.floor(remaining / 3600);
    var m = Math.floor((remaining % 3600) / 60);
    var s = remaining % 60;
    el.textContent =
      pad(h) + ':' + pad(m) + ':' + pad(s);

    // Colour shifts as session nears end
    if (remaining < 300) {
      el.style.color = 'var(--err-text)';
    } else if (remaining < 900) {
      el.style.color = 'var(--warn-text)';
    } else {
      el.style.color = 'var(--g400)';
    }
  }

  function pad(n) { return n < 10 ? '0' + n : String(n); }

  update();
  setInterval(update, 1000);
})();

/* ── Clipboard copy ───────────────────────────────────────── */
function copyToClipboard(text, btn) {
  if (!navigator.clipboard) {
    // Fallback
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try { document.execCommand('copy'); } catch (_) {}
    document.body.removeChild(ta);
    flashBtn(btn, 'Copied');
    return;
  }
  navigator.clipboard.writeText(text).then(function () {
    flashBtn(btn, 'Copied');
  }).catch(function () {
    flashBtn(btn, 'Failed');
  });
}

function flashBtn(btn, label) {
  if (!btn) return;
  var orig = btn.textContent;
  btn.textContent = label;
  btn.disabled = true;
  setTimeout(function () {
    btn.textContent = orig;
    btn.disabled = false;
  }, 1500);
}
