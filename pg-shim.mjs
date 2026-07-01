// Minimal supabase-js-compatible query builder backed by node-postgres, so the enclave
// talks to Postgres directly AS the narrow `guard_enclave` role instead of holding the
// full service-role PostgREST key. Supports exactly the call shapes the guard uses:
//   from(t).select(cols).eq(c,v).maybeSingle()
//   from(t).insert(obj|obj[])  .update(obj).eq(...)  .upsert(obj,{onConflict})  .delete().eq(...)
//   .eq() / .is() / .gt() filters, .order(col, {ascending}) on selects
// Every result is { data, error } like supabase-js, so the worker code is unchanged.
import pg from "pg";
import tls from "node:tls";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// Identifiers come only from our own source (never user input), but hard-allowlist
// anyway so a typo can never become injection. Values always go through $N params.
function ident(name) {
  if (!/^[a-z_][a-z0-9_]*$/i.test(name)) throw new Error(`bad identifier: ${name}`);
  return `"${name}"`;
}
function colList(sel) {
  if (!sel || sel === "*") return "*";
  return sel
    .split(",")
    .map((c) => ident(c.trim()))
    .join(", ");
}

export class QB {
  constructor(pool, table) {
    this.pool = pool;
    this.table = table;
    this._op = "select";
    this._cols = "*";
    this._where = [];
    this._values = null;
    this._onConflict = null;
    this._single = false;
  }
  select(c) {
    if (this._op === "select") this._cols = c || "*";
    return this;
  }
  insert(v) {
    this._op = "insert";
    this._values = v;
    return this;
  }
  update(v) {
    this._op = "update";
    this._values = v;
    return this;
  }
  upsert(v, opts) {
    this._op = "upsert";
    this._values = v;
    this._onConflict = opts?.onConflict;
    return this;
  }
  delete() {
    this._op = "delete";
    return this;
  }
  eq(c, v) {
    this._where.push(["=", c, v]);
    return this;
  }
  is(c, v) {
    // F32: only IS NULL / IS TRUE / IS FALSE are meaningful; anything else used to
    // silently coerce to IS NULL. Refuse unsupported values rather than build a
    // wrong-but-silent predicate.
    if (v !== null && v !== true && v !== false) throw new Error(`unsupported .is(${c}, ${v}) value`);
    this._where.push(["is", c, v]);
    return this;
  }
  gt(c, v) {
    this._where.push([">", c, v]);
    return this;
  }
  in(c, arr) {
    this._where.push(["in", c, Array.isArray(arr) ? arr : [arr]]);
    return this;
  }
  // supabase-js negation — the worker only ever uses .not(col, "is", null) → IS NOT NULL
  not(c, op, v) {
    if (op !== "is" || v !== null) throw new Error(`unsupported not(): ${op} ${v}`);
    this._where.push(["isnot", c, null]);
    return this;
  }
  order(c, opts) {
    this._order = { col: c, asc: opts?.ascending !== false };
    return this;
  }
  maybeSingle() {
    this._single = true;
    return this;
  }
  single() {
    this._single = true;
    return this;
  }
  // Thenable: awaiting the builder runs the query (mirrors supabase-js).
  then(resolve, reject) {
    return this._run().then(resolve, reject);
  }

  _whereSql(params) {
    if (!this._where.length) return "";
    const parts = this._where.map(([op, c, v]) => {
      if (op === "is") return `${ident(c)} IS ${v === null ? "NULL" : v === true ? "TRUE" : v === false ? "FALSE" : "NULL"}`;
      if (op === "isnot") return `${ident(c)} IS NOT NULL`;
      if (op === "in") {
        const placeholders = v.map((x) => { params.push(x); return `$${params.length}`; });
        return `${ident(c)} IN (${placeholders.join(", ") || "NULL"})`;
      }
      params.push(v);
      return `${ident(c)} ${op === ">" ? ">" : "="} $${params.length}`;
    });
    return " WHERE " + parts.join(" AND ");
  }

  async _run() {
    const params = [];
    try {
      if (this._op === "select") {
        let sql = `SELECT ${colList(this._cols)} FROM ${ident(this.table)}${this._whereSql(params)}`;
        if (this._order) sql += ` ORDER BY ${ident(this._order.col)} ${this._order.asc ? "ASC" : "DESC"}`;
        if (this._single) sql += " LIMIT 1";
        const r = await this.pool.query(sql, params);
        return { data: this._single ? (r.rows[0] ?? null) : r.rows, error: null };
      }
      if (this._op === "insert") {
        const rows = Array.isArray(this._values) ? this._values : [this._values];
        if (!rows.length) return { data: [], error: null };
        const keys = Object.keys(rows[0]);
        const tuples = rows
          .map((row) => "(" + keys.map((k) => { params.push(row[k]); return `$${params.length}`; }).join(", ") + ")")
          .join(", ");
        const sql = `INSERT INTO ${ident(this.table)} (${keys.map(ident).join(", ")}) VALUES ${tuples} RETURNING *`;
        const r = await this.pool.query(sql, params);
        return { data: this._single ? (r.rows[0] ?? null) : r.rows, error: null };
      }
      if (this._op === "update") {
        // F32: never issue an unfiltered UPDATE (would touch every row).
        if (!this._where.length) throw new Error(`refusing unfiltered UPDATE on ${this.table}`);
        const keys = Object.keys(this._values);
        const setSql = keys.map((k) => { params.push(this._values[k]); return `${ident(k)} = $${params.length}`; }).join(", ");
        const sql = `UPDATE ${ident(this.table)} SET ${setSql}${this._whereSql(params)} RETURNING *`;
        const r = await this.pool.query(sql, params);
        return { data: r.rows, error: null };
      }
      if (this._op === "upsert") {
        const row = Array.isArray(this._values) ? this._values[0] : this._values;
        const keys = Object.keys(row);
        const vals = keys.map((k) => { params.push(row[k]); return `$${params.length}`; }).join(", ");
        const conflict = this._onConflict || keys[0];
        const upd = keys
          .filter((k) => k !== conflict)
          .map((k) => `${ident(k)} = EXCLUDED.${ident(k)}`)
          .join(", ");
        const doUpdate = upd ? `DO UPDATE SET ${upd}` : "DO NOTHING";
        const sql = `INSERT INTO ${ident(this.table)} (${keys.map(ident).join(", ")}) VALUES (${vals}) ON CONFLICT (${ident(conflict)}) ${doUpdate} RETURNING *`;
        const r = await this.pool.query(sql, params);
        return { data: this._single ? (r.rows[0] ?? null) : r.rows, error: null };
      }
      if (this._op === "delete") {
        // F32: never issue an unfiltered DELETE (would wipe the table).
        if (!this._where.length) throw new Error(`refusing unfiltered DELETE on ${this.table}`);
        const sql = `DELETE FROM ${ident(this.table)}${this._whereSql(params)}`;
        await this.pool.query(sql, params);
        return { data: null, error: null };
      }
      throw new Error(`unsupported op ${this._op}`);
    } catch (e) {
      return { data: null, error: { message: e?.message || String(e) } };
    }
  }
}

// The parent host relays the enclave's network (TAP/gvproxy) and is UNTRUSTED, so it
// could MITM Postgres and capture the guard_enclave credential (or feed forged rows).
// We pin Supabase's private root CA (committed + baked into the measured image) and
// require full chain verification: a MITM parent cannot present a cert that chains to
// this root without Supabase's private key. FAIL CLOSED — if the pinned CA is missing
// we refuse to connect rather than fall back to an unverified TLS session.
function supabaseCa() {
  try {
    return readFileSync(fileURLToPath(new URL("./supabase-ca.pem", import.meta.url)), "utf8");
  } catch (e) {
    throw new Error(`pinned Supabase CA (supabase-ca.pem) missing/unreadable — refusing unverified DB TLS: ${e?.message}`);
  }
}

// F16: RFC-6125 hostname check FIRST (Node's standard verifier), THEN the pinned
// host-suffix allowlist as defense-in-depth — no weak substring matching.
function checkServerIdentity(host, cert) {
  const err = tls.checkServerIdentity(host, cert);
  if (err) return err;
  if (!/(^|\.)(pooler\.supabase\.com|supabase\.co)$/.test(host)) {
    return new Error(`unexpected DB host (not a Supabase endpoint): ${host}`);
  }
  return undefined;
}

/**
 * Create a supabase-js-shaped client backed by a direct guard_enclave PG connection.
 * F15: NEVER pass the raw connection string to pg (URL ssl/sslmode params merge OVER
 * and can silently drop the pinned CA). Parse it ourselves, HARD-REJECT any ssl param
 * (fail closed), and build the pool from discrete fields + our explicit, pinned ssl.
 */
export function createPgDb(connectionString) {
  const ca = supabaseCa();
  const u = new URL(connectionString);
  for (const [k] of u.searchParams) {
    if (/^ssl/i.test(k)) throw new Error(`GUARD_DB_URL must not carry ssl params (found '${k}') — pinned TLS only`);
  }
  const ssl = { ca, rejectUnauthorized: true, checkServerIdentity };
  const pool = new pg.Pool({
    host: u.hostname,
    port: u.port ? Number(u.port) : 5432,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: u.pathname.replace(/^\//, "") || "postgres",
    ssl,
    max: 4,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  });
  // Post-construction assertion: the pin must be in force, never silently degraded.
  if (pool.options?.ssl?.ca !== ca || pool.options?.ssl?.rejectUnauthorized !== true) {
    throw new Error("pinned-CA TLS not in force after pool construction — refusing to start");
  }
  pool.on("error", () => {}); // don't crash on idle-client errors; queries surface their own

  // rpc(fn, args): call a public.* function by NAMED args. The function name and
  // arg names are NOT parameterizable, so they are strictly identifier-validated
  // (fail closed); every VALUE is a bound parameter. Used only for the gateway-
  // only seal/onboarding functions (0032). A function RAISE (e.g. a failed seal
  // CAS) rejects here, so the caller aborts the ceremony rather than proceeding on
  // a phantom commit.
  const IDENT = /^[a-z_][a-z0-9_]*$/i;
  async function rpc(fn, args = {}) {
    if (!IDENT.test(fn)) throw new Error(`rpc: invalid function name ${fn}`);
    const keys = Object.keys(args);
    for (const k of keys) if (!IDENT.test(k)) throw new Error(`rpc: invalid arg name ${k}`);
    const named = keys.map((k, i) => `${k} => $${i + 1}`).join(", ");
    const r = await pool.query(`SELECT public.${fn}(${named})`, keys.map((k) => args[k]));
    return r.rows?.[0] ?? null;
  }

  return { from: (table) => new QB(pool, table), rpc, _pool: pool };
}
