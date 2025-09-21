// Small helper to centralize Authorization header logic and fetch wrapper
export function getTokenFromAuth(auth) {
  if (!auth) return null;
  if (auth.accessToken) return auth.accessToken;
  if (auth.token) return auth.token; // backward compat
  return null;
}

import { API_BASE } from './config';

export async function authFetch(url, options = {}, auth, opts = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (!headers['Authorization'] && !headers['authorization']) {
    const token = getTokenFromAuth(auth);
    if (token) headers['Authorization'] = 'Bearer ' + token;
  }
  const target = url.startsWith('http') ? url : (API_BASE + url);
  const res = await fetch(target, Object.assign({}, options, { headers }));
  // If unauthorized, try refreshing once using cookie-based refresh endpoint
  if (res.status === 401 && auth && !opts._retried) {
    try {
  const r = await fetch(API_BASE + '/api/refresh', { method: 'POST', credentials: 'include' });
      if (r.ok) {
        const body = await r.json();
        // update stored auth (only accessToken; refresh is in HttpOnly cookie)
        auth.accessToken = body.accessToken;
        if (body.roles) auth.roles = body.roles;
        localStorage.setItem('minisnap_auth', JSON.stringify(auth));
        // retry original request once
        return authFetch(url, options, auth, { _retried: true });
      }
    } catch (e) { /* ignore */ }
  }
  return res;
}

// Helper to produce a Sec-WebSocket-Protocol token that matches what server expects
export function wsProtocolToken(auth) {
  const token = getTokenFromAuth(auth);
  if (!token) return null;
  // If it's a JWT (contains a dot) return it raw; else convert to v1.base64url
  if (token.indexOf('.') !== -1) return token;
  // base64 -> base64url
  const b64url = token.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return 'v1.' + b64url;
}
