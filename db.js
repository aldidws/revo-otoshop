require("dotenv").config();
const { Pool } = require("pg");

const connectionString = process.env.DATABASE_URL;

// Enable SSL for any remote/managed Postgres (Render, Neon, Supabase, Heroku, etc.).
// Only skip SSL for a purely local database.
const isLocal =
  /@(localhost|127\.0\.0\.1|\[::1\])(:|\/)/.test(connectionString || "");

const pool = new Pool({
  connectionString,
  ssl: isLocal ? false : { rejectUnauthorized: false },
});

module.exports = pool;
