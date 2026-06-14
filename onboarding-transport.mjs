// gateway/onboarding-transport.mjs: the ONBOARDING-mode transport (spec 4.10).
// The Telegram operations the OnboardingManager drives, over an ONBOARDING-mode
// connection (connection.mjs). Mirrors makeArmedTransport but for the login
// ceremony: send code, sign in, SRP, identity readback, logout, and the
// enclave-only session export the seal consumes.
//
// SECURITY INVARIANTS enforced here:
//   - the chokepoint (bound in the connection) gates every send to the closed
//     ONBOARDING allowlist (auth.sendCode/signIn/checkPassword + account.getPassword
//     + users.getUsers self + auth.logOut); this module cannot widen it;
//   - the raw 2FA PASSWORD is NEVER seen here. The browser computes the SRP proof
//     (A, M1) from the public params and the password; this transport only relays
//     the public params out and the proof in. We hold the single-use srpId between
//     getPassword and checkPassword so the proof binds to the exact challenge;
//   - exportSession() returns the StringSession ({dc,addr,port,auth_key}) ONLY so
//     sealEnvelopeV3 can seal it. It is never returned over the channel or to the DB.
//
// Telegram RPC error strings are mapped to the EXACT messages the OnboardingManager
// branches on. Pre-sign-in DC migration remains explicit so the manager can cold
// switch, rotate the durable recovery envelope, and only then retry sendCode.

import { Api } from "telegram";
import { MODES } from "./tg-chokepoint.mjs";
import { publicAuthFields } from "./mtproto-client.mjs";

const TG_CODES = [
  "SESSION_PASSWORD_NEEDED", "PHONE_CODE_INVALID", "PHONE_CODE_EXPIRED",
  "PASSWORD_HASH_INVALID", "PHONE_NUMBER_INVALID", "PHONE_NUMBER_BANNED",
  "PHONE_NUMBER_FLOOD", "PHONE_PASSWORD_FLOOD", "AUTH_RESTART",
];

function mapTgError(e) {
  const m = String(e?.errorMessage ?? e?.message ?? e);
  const migration = /(PHONE|NETWORK|USER)_MIGRATE_(\d+)/i.exec(m);
  if (migration) return new Error(`${migration[1].toUpperCase()}_MIGRATE_${migration[2]}`);

  // GramJS exposes the target as `newDc` and rewrites Telegram's canonical
  // migration code into a human-readable "... associated with DC N" message.
  const humanMigration = /associated with DC\s+(\d+)/i.exec(m);
  const migratedDc = Number(e?.newDc ?? humanMigration?.[1]);
  if (Number.isInteger(migratedDc) && migratedDc > 0) {
    const errorName = String(e?.constructor?.name ?? "");
    let migrationType = null;
    if (/PhoneMigrateError/i.test(errorName) || /phone number/i.test(m)) {
      migrationType = "PHONE";
    } else if (/UserMigrateError/i.test(errorName) || /user identity/i.test(m)) {
      migrationType = "USER";
    } else if (/NetworkMigrateError/i.test(errorName) || /source IP/i.test(m)) {
      migrationType = "NETWORK";
    }
    if (migrationType) return new Error(`${migrationType}_MIGRATE_${migratedDc}`);
  }
  for (const code of TG_CODES) if (m.includes(code)) return new Error(code);
  return e instanceof Error ? e : new Error(m);
}

// Serialize the PUBLIC SRP KDF params the browser needs to derive A, M1. Contains
// no secret: salts, the group (g, p), and the server ephemeral srpB. The password
// never reaches the gateway.
function serializeSrp(pwd) {
  const b64 = (x) => (x ? Buffer.from(x).toString("base64") : null);
  const algo = pwd.currentAlgo;
  return {
    srpId: pwd.srpId != null ? String(pwd.srpId) : null,
    srpB: b64(pwd.srpB),
    hasPassword: !!pwd.hasPassword,
    algo: algo
      ? {
          type: algo.className ?? algo.constructor?.name ?? null,
          g: typeof algo.g === "number" ? algo.g : null,
          p: b64(algo.p),
          salt1: b64(algo.salt1),
          salt2: b64(algo.salt2),
        }
      : null,
  };
}

export async function makeOnboardingTransport({ conn, apiId, apiHash }) {
  if (!conn?.chokepoint || conn.chokepoint.mode !== MODES.ONBOARDING) {
    throw new Error("onboarding transport requires an ONBOARDING connection");
  }
  let srpId = null; // single-use, set by getPassword, consumed by checkPassword

  return {
    connect: () => conn.connect(),
    disconnect: () => conn.disconnect(),
    migrateOnboardingDc: (dcId) => conn.migrateOnboardingDc(dcId),

    // The freshly-minted session, for sealing ONLY. Stays inside the enclave.
    exportSession: () => conn.session.save(),

    async sendCode({ phone }) {
      try {
        const res = await conn.invoke(new Api.auth.SendCode({
          phoneNumber: phone, apiId: Number(apiId), apiHash: String(apiHash),
          settings: new Api.CodeSettings({}),
        }));
        return {
          phoneCodeHash: res.phoneCodeHash,
          isCodeViaApp: res.type instanceof Api.auth.SentCodeTypeApp,
        };
      } catch (e) { throw mapTgError(e); }
    },

    async signIn({ phone, hash, code }) {
      try {
        await conn.invoke(new Api.auth.SignIn({ phoneNumber: phone, phoneCodeHash: hash, phoneCode: code }));
        return {};
      } catch (e) { throw mapTgError(e); }
    },

    async getPassword() {
      const pwd = await conn.invoke(new Api.account.GetPassword());
      srpId = pwd.srpId; // BigInt; bind the next checkPassword to this exact challenge
      return serializeSrp(pwd);
    },

    async checkPassword({ A, M1 }) {
      if (srpId == null) throw new Error("checkPassword before getPassword");
      try {
        await conn.invoke(new Api.auth.CheckPassword({
          password: new Api.InputCheckPasswordSRP({
            srpId, A: Buffer.from(A, "base64"), M1: Buffer.from(M1, "base64"),
          }),
        }));
        srpId = null; // single use
        return {};
      } catch (e) { throw mapTgError(e); }
    },

    async getMe() {
      const res = await conn.invoke(new Api.users.GetUsers({ id: [new Api.InputUserSelf()] }));
      const me = Array.isArray(res) ? res[0] : res;
      return { tgUserId: String(me.id), firstName: me.firstName ?? null, username: me.username ?? null };
    },

    // Read-only session roster for the onboarding "keep" step. account.getAuthorizations
    // is in the general chokepoint allowlist (permitted in BOTH modes; it is NOT an
    // ARMED_ONLY mutating op), so this needs no allowlist change. Returns only the
    // PUBLIC fields (publicAuthFields) — no auth_key, no session string.
    async listSessions() {
      const res = await conn.invoke(new Api.account.GetAuthorizations());
      return (res.authorizations ?? []).map(publicAuthFields);
    },

    async logOut() {
      // ONBOARDING-mode auth.logOut is the gateway-internal case-3 teardown revoke.
      // The chokepoint blocks it UNLESS the teardown grant is bound — and it must be
      // bound on the chokepoint instance so the AUTHORITATIVE audited seam (which
      // validates without per-call hooks) authorizes it, not silently swallows it,
      // leaving a live Telegram authorization the guard believes it revoked.
      conn.chokepoint.bindTeardown(true);
      try { await conn.invoke(new Api.auth.LogOut()); }
      catch { /* a dead session is also gone */ }
      finally { conn.chokepoint.bindTeardown(false); }
      return {};
    },
  };
}

export { mapTgError, serializeSrp };
