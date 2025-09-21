import React, { useRef, useEffect, useState } from "react";
import { authFetch } from './api';


function Camera({ auth, onAuthError }) {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const [captured, setCaptured] = useState(null);
  const [ttl, setTtl] = useState('24h');
  const [users, setUsers] = useState([]);
  const [recipient, setRecipient] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    navigator.mediaDevices.getUserMedia({ video: true })
      .then((stream) => {
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
        }
      })
      .catch((err) => console.error("Error accessing webcam:", err));
    // fetch users for recipient dropdown
  authFetch('/api/users', {}, auth).then(r => {
      if (r.status === 401) {
        onAuthError && onAuthError();
        return [];
      }
      return r.json();
    }).then(list => setUsers(list || [])).catch(() => setUsers([]));
  }, []);

  const takeSnap = () => {
    const canvas = canvasRef.current;
    const video = videoRef.current;
    if (!canvas || !video) return;

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext("2d").drawImage(video, 0, 0);

    canvas.toBlob((blob) => {
      setCaptured(blob);
    }, "image/jpeg");
  };


  const uploadSnap = async () => {
    if (!captured) return;
    const formData = new FormData();
    formData.append("snap", captured, "snap.jpg");
    formData.append("ttl", ttl);
  if (recipient) formData.append('to', recipient);
  if (message) formData.append('message', message);

  const res = await authFetch('/api/snap', { method: "POST", body: formData }, auth);
    if (res.status === 401) {
      onAuthError && onAuthError();
      return;
    }

    alert("Snap uploaded!");
    setCaptured(null);
    setMessage("");
  };

  return (
    <div>
      <h2>Camera</h2>
      <video ref={videoRef} autoPlay playsInline style={{ width: "100%" }} />
      <canvas ref={canvasRef} style={{ display: "none" }} />

      <div style={{ marginTop: 10 }}>
        <label style={{ marginRight: 8 }}>To:</label>
        <select value={recipient} onChange={e => setRecipient(e.target.value)}>
          <option value="">(Public)</option>
          {users.map(u => (
            <option key={u} value={u}>{u}</option>
          ))}
        </select>
      </div>

      <div>
        <button onClick={takeSnap}>📸 Capture</button>
        {captured && (
          <>
            <img
              src={URL.createObjectURL(captured)}
              alt="Captured"
              style={{ width: "100%", marginTop: "10px" }}
            />
            <label style={{ marginLeft: 8 }}>
              TTL:
              <select value={ttl} onChange={e => setTtl(e.target.value)} style={{ marginLeft: 6 }}>
                <option value="24h">24 hours</option>
                <option value="viewOnce">One view only</option>
                <option value="indefinite">Keep indefinitely</option>
              </select>
            </label>
            <br />
            <button onClick={uploadSnap}>⬆️ Upload Snap</button>
          </>
        )}
      </div>
    </div>
  );
}

export default Camera;
