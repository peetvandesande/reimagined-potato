// Central backend configuration — read from env with sensible defaults
module.exports = {
  PORT: parseInt(process.env.PORT || '5000', 10),
  FRONTEND_ORIGIN: process.env.FRONTEND_ORIGIN || 'http://localhost:3000',
  REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
  DATABASE_URL: process.env.DATABASE_URL || null,
  JWT_SECRET: process.env.JWT_SECRET || 'dev-secret',
  ACCESS_TTL: process.env.ACCESS_TTL || '15m',
  REFRESH_TTL_SECONDS: parseInt(process.env.REFRESH_TTL_SECONDS || String(7 * 24 * 60 * 60), 10),
  COOKIE_SECURE: process.env.COOKIE_SECURE === '1',
  COOKIE_NAME: process.env.COOKIE_NAME || 'refreshToken',
  CHAT_CHANNEL: process.env.CHAT_CHANNEL || 'mini_snap_chat_channel',
  CHAT_STREAM: process.env.CHAT_STREAM || 'mini_snap_chat_stream',
  LAST_READ_PREFIX: process.env.LAST_READ_PREFIX || 'chat_last_read:',
  SNAP_PREFIX: process.env.SNAP_PREFIX || 'snap:',
  REFRESH_PREFIX: process.env.REFRESH_PREFIX || 'refresh:',
  REVOKED_JTI_PREFIX: process.env.REVOKED_JTI_PREFIX || 'revoked_jti:',
  UPLOADS_DIR: process.env.UPLOADS_DIR || 'uploads',

  // LDAP configuration (optional). Set LDAP_URL to enable LDAP auth in /api/login
  LDAP_URL: process.env.LDAP_URL || '',
  LDAP_BASE_DN: process.env.LDAP_BASE_DN || 'dc=example,dc=org',
  LDAP_PEOPLE_OU: process.env.LDAP_PEOPLE_OU || 'ou=people',
  LDAP_GROUPS_OU: process.env.LDAP_GROUPS_OU || 'ou=groups',

  // LDAP caching (store group membership in Redis to reduce LDAP queries)
  LDAP_CACHE_PREFIX: process.env.LDAP_CACHE_PREFIX || 'ldap_roles:',
  LDAP_CACHE_TTL_SECONDS: parseInt(process.env.LDAP_CACHE_TTL_SECONDS || '3600', 10)
};
// prefix for marking one-time chat message delivery
module.exports.CHAT_DELIVERED_PREFIX = process.env.CHAT_DELIVERED_PREFIX || 'chat_delivered:';



