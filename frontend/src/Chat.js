import React, { useEffect, useState, useRef } from 'react';
import { authFetch, wsProtocolToken } from './api';
import { WS_BASE, API_BASE } from './config';

function Chat({ auth, onAuthError }) {
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState('');
  const [ttl, setTtl] = useState('24h');
  const wsRef = useRef(null);
  const seenIdsRef = useRef(new Set());

  useEffect(() => {
    let shouldStop = false;
  const token = auth.token || btoa(`${auth.username}:${auth.password}`);
    let backoff = 500; // ms
    async function fetchHistory() {
      try {
  const res = await authFetch('/api/chat/history?count=100', {}, auth);
        if (!res.ok) return;
        const body = await res.json();
        if (body && body.msgs && Array.isArray(body.msgs)) {
          const toAdd = [];
          for (const m of body.msgs) {
            if (m.id && !seenIdsRef.current.has(m.id)) {
              seenIdsRef.current.add(m.id);
              toAdd.push(m);
            }
          }
          if (toAdd.length) setMessages(prev => [...prev, ...toAdd]);
        }
      } catch (e) { console.error('history fetch failed', e); }
    }

    function connect() {
      if (shouldStop) return;
  // Pass token via Sec-WebSocket-Protocol as a v1.<base64url> token (or raw JWT)
  const protoToken = wsProtocolToken(auth);
  const ws = new WebSocket(`${WS_BASE}/api/chat/ws`, protoToken);
      ws.onopen = () => {
        console.log('ws open');
        backoff = 500;
        // fetch recent history on each successful connect so we sync missed messages
        fetchHistory();
      };
      ws.onmessage = (e) => {
        try {
          const m = JSON.parse(e.data);
          if (m && m.id) {
            if (seenIdsRef.current.has(m.id)) return;
            seenIdsRef.current.add(m.id);
          }
          setMessages(prev => [...prev, m]);
        } catch (err) {}
      };
      ws.onclose = () => {
        if (shouldStop) return;
        const jitter = Math.random() * 300;
        const wait = Math.min(30000, backoff + jitter);
        console.log('ws closed, reconnecting in', Math.round(wait));
        setTimeout(() => { backoff = Math.min(30000, backoff * 1.5); connect(); }, wait);
      };
      ws.onerror = (e) => console.error('ws err', e);
      wsRef.current = ws;
    }
    connect();
    return () => { try { ws.close(); } catch(e){} };
  }, [auth.username, auth.password]);

  const send = () => {
    if (!text.trim()) return;
    const ws = wsRef.current;
    const payload = { text, ttl };
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
  else authFetch('/api/chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }, auth);
    setText('');
  };

  return (
    <div style={{ marginTop: 20 }}>
      <h2>Chat</h2>
      <div style={{ height: 200, overflow: 'auto', border: '1px solid #eee', padding: 8 }}>
        {messages.map(m => (
          <div key={m.id || Math.random()}><strong>{m.from}</strong>: {m.text}</div>
        ))}
      </div>
      <div style={{ marginTop: 8 }}>
        <input value={text} onChange={e => setText(e.target.value)} placeholder="Say something" />
        <select value={ttl} onChange={e => setTtl(e.target.value)} style={{ marginLeft: 8 }}>
          <option value="24h">24 hours</option>
          <option value="viewOnce">One view only</option>
          <option value="indefinite">Keep indefinitely</option>
        </select>
        <button onClick={send} style={{ marginLeft: 6 }}>Send</button>
      </div>
    </div>
  );
}

export default Chat;
