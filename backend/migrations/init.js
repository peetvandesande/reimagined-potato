const { Pool } = require('pg');
const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
  console.log('No DATABASE_URL set, skipping migrations');
  process.exit(0);
}

const pool = new Pool({ connectionString: dbUrl });

(async function migrate() {
  try {
    console.log('Running DB migrations...');
    await pool.query('SELECT 1');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS snaps (
        id TEXT PRIMARY KEY,
        sender TEXT,
        recipients TEXT[],
        file TEXT,
        time BIGINT,
        expiresAt BIGINT,
        viewOnce BOOLEAN,
        message TEXT
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        snap_id TEXT REFERENCES snaps(id) ON DELETE CASCADE,
        user_name TEXT,
        text TEXT,
        time BIGINT
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS read_marks (
        snap_id TEXT REFERENCES snaps(id) ON DELETE CASCADE,
        user_name TEXT,
        PRIMARY KEY (snap_id, user_name)
      )
    `);
    console.log('Migrations complete');
  } catch (err) {
    console.error('Migration failed', err);
    process.exit(1);
  } finally {
    await pool.end();
  }
  process.exit(0);
})();
