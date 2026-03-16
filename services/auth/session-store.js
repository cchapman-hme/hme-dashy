// services/auth/session-store.js
// SQLite-backed express-session store (no Redis dependency required)
'use strict';

const session = require('express-session');
const Database = require('better-sqlite3');
const { existsSync, mkdirSync } = require('node:fs');
const { dirname } = require('node:path');

const SESSION_DB_PATH = process.env.SESSION_DB_PATH || './data/sessions.db';

class SessionStore extends session.Store {
  constructor() {
    super();
    const dir = dirname(SESSION_DB_PATH);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

    this.db = new Database(SESSION_DB_PATH);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        sid     TEXT    PRIMARY KEY,
        data    TEXT    NOT NULL,
        expires INTEGER NOT NULL
      )
    `);
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_expires ON sessions(expires)');

    // Prepared statements for fast CRUD
    this._get   = this.db.prepare('SELECT data FROM sessions WHERE sid = ? AND expires > ?');
    this._set   = this.db.prepare('INSERT OR REPLACE INTO sessions (sid, data, expires) VALUES (?, ?, ?)');
    this._del   = this.db.prepare('DELETE FROM sessions WHERE sid = ?');
    this._prune = this.db.prepare('DELETE FROM sessions WHERE expires <= ?');

    // Prune expired sessions every 15 minutes
    this._pruneInterval = setInterval(() => this.prune(), 15 * 60 * 1000);
    this._pruneInterval.unref(); // don't block process exit
  }

  get(sid, cb) {
    try {
      const row = this._get.get(sid, Date.now());
      cb(null, row ? JSON.parse(row.data) : null);
    } catch (e) { cb(e); }
  }

  set(sid, data, cb) {
    try {
      const maxAge = (data.cookie && data.cookie.maxAge) ? data.cookie.maxAge : 8 * 60 * 60 * 1000;
      this._set.run(sid, JSON.stringify(data), Date.now() + maxAge);
      if (cb) cb(null);
    } catch (e) { if (cb) cb(e); }
  }

  destroy(sid, cb) {
    try {
      this._del.run(sid);
      if (cb) cb(null);
    } catch (e) { if (cb) cb(e); }
  }

  prune() {
    this._prune.run(Date.now());
  }

  close() {
    clearInterval(this._pruneInterval);
    this.db.close();
  }
}

module.exports = { SessionStore };
