/**
 * HCaja Session Guard
 * Validates session before allowing iframe content to load
 * 
 * Usage in leave_report.html / issue_sum.html:
 *   <script src="hcaja-session-guard.js"></script>
 *   (Session will be checked automatically on load)
 */

(function() {
  'use strict';

  const SESSION_KEY = 'hcaja_session';
  const TAB_AUTH_KEY = 'hcaja_tab_authenticated';
  const SESSION_MAX_AGE = 8 * 60 * 60 * 1000; // 8 jam
  const SESSION_SECRET = 'ed1068cb08e146daa58613083eda8899abb8a2c7a3c54347af53773d7168ec90';

  async function sha256(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function isSessionValid() {
    try {
      // Per-tab check
      if (!sessionStorage.getItem(TAB_AUTH_KEY)) return false;

      const raw = sessionStorage.getItem(SESSION_KEY);
      if (!raw) return false;

      const s = JSON.parse(raw);
      if (!s.token || !s.proof || !s.issuedAt) return false;
      if (Date.now() - s.issuedAt > SESSION_MAX_AGE) return false;

      const expected = await sha256(s.token + ':' + SESSION_SECRET);
      return expected === s.proof;
    } catch (e) {
      return false;
    }
  }

  // Check on load
  document.documentElement.style.visibility = 'hidden';
  
  isSessionValid().then(function(valid) {
    if (valid) {
      document.documentElement.style.visibility = 'visible';
    } else {
      window.location.replace('index.html?blocked=1');
    }
  });
})();
