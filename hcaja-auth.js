/**
 * HCaja Authentication & Session Management
 * Per-tab session security (Opsi C)
 * 
 * Usage:
 *   <script src="hcaja-auth.js"></script>
 *   <script>
 *     HCajaAuth.init({
 *       passwordHash: 'f92b9e51...',
 *       sessionSecret: 'ed1068cb...',
 *       onSuccess: () => { ... },
 *       onFail: () => { ... }
 *     });
 *   </script>
 */

const HCajaAuth = (function() {
  'use strict';

  // Configuration
  let config = {
    passwordHash: '',
    sessionSecret: '',
    onSuccess: null,
    onFail: null
  };

  // Constants
  const SESSION_KEY = 'hcaja_session';
  const SESSION_MAX_AGE = 8 * 60 * 60 * 1000; // 8 jam
  const ATTEMPTS_KEY = 'hcaja_attempts';
  const LOCK_UNTIL_KEY = 'hcaja_lock_until';
  const TAB_AUTH_KEY = 'hcaja_tab_authenticated';

  // -------- CRYPTO HELPERS --------
  async function sha256(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function randomToken() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // -------- RATE LIMITING --------
  function getAttempts() {
    return parseInt(sessionStorage.getItem(ATTEMPTS_KEY) || '0', 10);
  }

  function setAttempts(n) {
    sessionStorage.setItem(ATTEMPTS_KEY, String(n));
  }

  function getLockUntil() {
    return parseInt(sessionStorage.getItem(LOCK_UNTIL_KEY) || '0', 10);
  }

  function setLockUntil(ts) {
    sessionStorage.setItem(LOCK_UNTIL_KEY, String(ts));
  }

  function lockDurationFor(attempts) {
    if (attempts >= 12) return 10 * 60 * 1000;
    if (attempts >= 8) return 2 * 60 * 1000;
    if (attempts >= 5) return 30 * 1000;
    return 0;
  }

  // -------- SESSION MANAGEMENT --------
  async function issueSession() {
    const token = randomToken();
    const proof = await sha256(token + ':' + config.sessionSecret);
    const session = { token, proof, issuedAt: Date.now() };
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
    // Per-tab authentication marker (Opsi C)
    sessionStorage.setItem(TAB_AUTH_KEY, '1');
    sessionStorage.removeItem(ATTEMPTS_KEY);
    sessionStorage.removeItem(LOCK_UNTIL_KEY);
  }

  async function isSessionValid() {
    try {
      // Per-tab check: has this tab been authenticated?
      if (!sessionStorage.getItem(TAB_AUTH_KEY)) return false;

      const raw = sessionStorage.getItem(SESSION_KEY);
      if (!raw) return false;

      const s = JSON.parse(raw);
      if (!s.token || !s.proof || !s.issuedAt) return false;
      if (Date.now() - s.issuedAt > SESSION_MAX_AGE) return false;

      const expected = await sha256(s.token + ':' + config.sessionSecret);
      return expected === s.proof;
    } catch (e) {
      return false;
    }
  }

  function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(TAB_AUTH_KEY);
    sessionStorage.removeItem(ATTEMPTS_KEY);
    sessionStorage.removeItem(LOCK_UNTIL_KEY);
  }

  // -------- PUBLIC API --------
  return {
    init(options) {
      config = { ...config, ...options };
    },

    async validatePassword(password) {
      const lockUntil = getLockUntil();
      const remaining = lockUntil - Date.now();

      if (remaining > 0) {
        return {
          success: false,
          locked: true,
          remainingMs: Math.max(0, remaining)
        };
      }

      const hash = await sha256(password);
      if (hash === config.passwordHash) {
        await issueSession();
        return { success: true, locked: false };
      } else {
        const attempts = getAttempts() + 1;
        setAttempts(attempts);
        const lockMs = lockDurationFor(attempts);

        if (lockMs > 0) {
          setLockUntil(Date.now() + lockMs);
        }

        return {
          success: false,
          locked: lockMs > 0,
          attempts,
          remainingMs: lockMs,
          message: lockMs > 0
            ? `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil(lockMs / 1000)} detik.`
            : `Password salah. Percobaan ke-${attempts}.`
        };
      }
    },

    async checkSession() {
      return await isSessionValid();
    },

    logout() {
      clearSession();
    },

    async boot() {
      return await this.checkSession();
    }
  };
})();
