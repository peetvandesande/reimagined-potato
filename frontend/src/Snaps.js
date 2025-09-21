import React, { useState, useEffect } from "react";
import { authFetch } from './api';
import { API_BASE } from './config';
import { removeSnapById } from './utils/snaps';


function Snaps({ auth, onAuthError }) {
  const [snaps, setSnaps] = useState([]);

  const fetchSnaps = () => {
  authFetch('/api/snaps', {}, auth)
      .then((res) => {
        if (res.status === 401) {
          onAuthError && onAuthError();
          throw new Error("Unauthorized");
        }
        return res.json();
      })
      .then(all => {
        // only show snaps that are public (no recipients) or addressed to this user
        const visible = all.filter(s => !s.recipients || s.recipients.length === 0 || s.recipients.includes(auth.username));
        setSnaps(visible);
      })
      .catch(() => setSnaps([]));
  };

  useEffect(() => {
    // refetch when auth.username changes (login flow may set username after mount)
    console.debug('Snaps mounted/refetch, auth:', auth && auth.username);
    fetchSnaps();
    const interval = setInterval(fetchSnaps, 10000);
    return () => clearInterval(interval);
    // eslint-disable-next-line
  }, [auth && auth.username]);

  const timeRemaining = (expiresAt) => {
    const diff = Math.max(0, expiresAt - Date.now());
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    return `${hours}h ${mins}m left`;
  };

  return (
    <div>
      <h2>Snaps Feed</h2>
      {snaps.length === 0 && <p>No snaps available.</p>}
      {snaps.map((snap) => (
  <div key={snap.id} style={{ marginBottom: "15px", border: '1px solid #eee', padding: 8, borderRadius: 6 }}>
          <img
            src={`${API_BASE}/uploads/${snap.file}`}
            alt="Snap"
            style={{ width: "100%", borderRadius: "10px" }}
            onError={e => (e.target.style.display = 'none')}
          />
          <div>
            <small style={{ display: 'block' }}>From: {snap.sender || 'unknown'}</small>
            <small style={{ display: 'block' }}>To: {snap.recipients && snap.recipients.length ? snap.recipients.join(', ') : 'Public'}</small>
            {snap.viewOnce ? (
              <small>⚡ View Once (will disappear)</small>
            ) : (
              <small>{timeRemaining(snap.expiresAt)}</small>
            )}
          </div>
          <div style={{ marginTop: 6 }}>
            <div style={{ fontStyle: 'italic' }}>{snap.message}</div>
            <div>
              <strong>Comments:</strong>
              {(snap.comments || []).map((c, idx) => (
                <div key={idx} style={{ paddingLeft: 6 }}>{c.user}: {c.text}</div>
              ))}
            </div>
            <div style={{ marginTop: 6 }}>
              <div style={{ marginBottom: 6 }}>
                Status: {(snap.readBy && snap.readBy.includes(auth.username)) ? <span style={{color: 'green'}}>Read</span> : <span style={{color: 'red'}}>Unread</span>}
              </div>
              <div>
                {/* only allow comment/read if user is recipient or sender */}
                {((!snap.recipients || snap.recipients.length === 0) || snap.recipients.includes(auth.username) || snap.sender === auth.username) ? (
                  <>
                    <input placeholder="Add comment" id={`comment-${snap.id}`} />
                    <button onClick={async () => {
                      const input = document.getElementById(`comment-${snap.id}`);
                      const text = input.value.trim();
                      if (!text) return;
                      await authFetch(`/api/snaps/${snap.id}/comment`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) }, auth);
                      input.value = '';
                      fetchSnaps();
                    }}>Comment</button>
                    <button style={{ marginLeft: 8 }} onClick={async () => {
                      await authFetch(`/api/snaps/${snap.id}/read`, { method: 'POST' }, auth);
                      // If this was a view-once snap, remove it from local state immediately
                      if (snap.viewOnce) setSnaps(prev => removeSnapById(prev, snap.id));
                      else fetchSnaps();
                    }}>Mark as read</button>
                  </>
                ) : (
                  <div style={{ color: '#666' }}>You cannot comment or mark this snap.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export default Snaps;
