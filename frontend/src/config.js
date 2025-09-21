// Central frontend config — override via environment at build time if needed
export const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:5000';
export const WS_BASE = process.env.REACT_APP_WS_BASE || 'ws://localhost:5000';
export const FRONTEND_ORIGIN = process.env.REACT_APP_FRONTEND_ORIGIN || 'http://localhost:3000';
