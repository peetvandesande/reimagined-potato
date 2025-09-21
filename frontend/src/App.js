
import React, { useState } from "react";

import Camera from "./Camera";
import Snaps from "./Snaps";
import Login from "./Login";
import Chat from "./Chat";
import { authFetch } from './api';
import { API_BASE } from './config';


function App() {
  const [auth, setAuth] = useState(() => {
    const saved = localStorage.getItem("minisnap_auth");
    return saved ? JSON.parse(saved) : null;
  });

  const handleLogin = (authObj) => {
    setAuth(authObj);
    localStorage.setItem('minisnap_auth', JSON.stringify(authObj));
  };

  // validate saved credentials on mount
  React.useEffect(() => {
    if (!auth) return;
    const check = async () => {
      try {
    // Validate token and refresh roles by calling /api/me (this will also rotate refresh cookie if needed)
    const res = await authFetch('/api/me', {}, auth);
        if (res.status === 401) { handleLogout(); return; }
        const body = await res.json();
        if (body && body.username) {
          const newAuth = Object.assign({}, auth, { username: body.username, roles: body.roles || auth.roles || [] });
          setAuth(newAuth);
          localStorage.setItem('minisnap_auth', JSON.stringify(newAuth));
        }
      } catch (e) {
        // network error -> leave auth alone for offline/dev
      }
    };
    check();
    // eslint-disable-next-line
  }, []);

  const handleLogout = () => {
    // attempt to revoke refresh token
    try {
      // server holds refresh token in HttpOnly cookie; call logout with credentials to clear it
  fetch(API_BASE + '/api/logout', { method: 'POST', credentials: 'include' });
    } catch (e) {}
    setAuth(null);
    localStorage.removeItem("minisnap_auth");
  };

  if (!auth) {
    return <Login onLogin={handleLogin} />;
  }

  // Pass a logout callback to children so they can force logout on 401
  return (
    <div style={{ padding: "20px", maxWidth: "500px", margin: "auto" }}>
      <h1>MiniSnap</h1>
      <button style={{ float: "right" }} onClick={handleLogout}>Logout</button>
      {auth && auth.roles && auth.roles.includes('admins') && (
        <AdminPanel auth={auth} />
      )}
      <Camera auth={auth} onAuthError={handleLogout} />
      <Snaps auth={auth} onAuthError={handleLogout} />
  <Chat auth={auth} onAuthError={handleLogout} />
    </div>
  );
}

export default App;

function AdminPanel({ auth }) {
  const [counts, setCounts] = React.useState(null);
  const [loading, setLoading] = React.useState(false);

  const fetchCounts = async () => {
    setLoading(true);
    try {
      const res = await fetch(API_BASE + '/admin/snaps-counts', { headers: { 'Authorization': 'Bearer ' + auth.accessToken } });
      if (!res.ok) throw new Error('Failed');
      const body = await res.json();
      setCounts(body.counts || {});
    } catch (e) {
      setCounts(null);
    }
    setLoading(false);
  };

  React.useEffect(() => { fetchCounts(); }, []);

  return (
    <div style={{ marginBottom: 12 }}>
      <strong>Admin</strong>
      <button style={{ marginLeft: 8 }} onClick={fetchCounts}>Refresh counts</button>
      <button style={{ marginLeft: 8 }} onClick={async () => { try { await fetch(API_BASE + '/admin/cleanup', { method: 'POST', headers: { 'Authorization': 'Bearer ' + auth.accessToken } }); alert('Cleanup requested'); } catch (e) { alert('Failed'); } }}>Run cleanup</button>
      <div style={{ marginTop: 8 }}>
        {loading && <div>Loading...</div>}
        {counts && (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr><th style={{ textAlign: 'left' }}>User</th><th style={{ textAlign: 'right' }}>Pending</th></tr></thead>
            <tbody>
              {Object.keys(counts).map(k => (
                <tr key={k}><td style={{ borderTop: '1px solid #eee', padding: 6 }}>{k}</td><td style={{ borderTop: '1px solid #eee', padding: 6, textAlign: 'right' }}>{counts[k]}</td></tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
