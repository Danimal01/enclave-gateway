// gateway/mtproto-client.mjs: the gateway's OWN minimal MTProto client (spec
// 4.2 "The gateway runs its own minimal MTProto client, not stock
// TelegramClient").
//
// Because the gateway owns the raw sender and imports no high-level client
// modules, it implements the connection machinery TelegramClient otherwise
// provides, all in published code:
//   - auth-key handshake + InvokeWithLayer(InitConnection(help.getConfig));
//   - keepalive (updates.getState + Ping);
//   - explicit DC migration (auth.export/importAuthorization, chokepoint-
//     constrained);
//   - reconnect/backoff;
//   - the single-branch update reader filtered to UpdateNewAuthorization;
//   - whoAmI self-identity (binding-2), replacing GramJS's lazy getMe.
//
// THE CONNECTION-WRITE STRUCTURE (spec 4.3). There are EXACTLY TWO sites in this
// client + its forked connection that write bytes to the socket:
//   WRITE SITE 1 (plaintext): the auth-key handshake writer, restricted to the
//     exact req_pq_multi / req_DH_params / set_client_DH_params state machine.
//     No generic TL-object or raw-byte send API exists on it.
//   WRITE SITE 2 (encrypted): the audited MTProtoSender serialization site,
//     where installAuditedSerialization (audited-sender.mjs) runs
//     assertAllowed(state.request) on every dequeued RequestState before
//     _state.encryptMessageData. gzip_packed sits BELOW this check.
// These are the only two byte-writing sites; adding a Telegram request, a
// plaintext handshake message, or another socket writer would change this
// published file (and therefore PCR0_G).
//
// LIVE-CONNECT NOTE: the actual socket bring-up, the auth-key handshake, and the
// DC-migration dance run only inside the enclave against real Telegram DCs. This
// module defines the published structure, the chokepoint binding, the
// keepalive/reconnect policy, and the update filter. The GramJS connection
// primitives it builds on are pinned by lockfile.

import { Api } from "telegram";
import { MODES } from "./tg-chokepoint.mjs";

const KEEPALIVE_MS = 30 * 60 * 1000;

// The single-branch update reader (spec 2.3, 4.5): the handler reads ONLY the
// new-login update and emits exactly four fields; every other update type,
// including all message updates, falls through unread in the same tick.
export function filterUpdate(update) {
  if (update instanceof Api.UpdateNewAuthorization) {
    return {
      hash: String(update.hash),
      unconfirmed: !!update.unconfirmed,
      device: update.device ?? null,
      location: update.location ?? null,
    };
  }
  return null; // dropped: never inspected, stored, or forwarded
}

// Telegram pushes updates WRAPPED in a standard container, and the low-level sender
// hands us that raw container (MTProtoSender._handleUpdate passes message.obj). A new
// login arrives as Api.Updates / Api.UpdatesCombined (.updates[]) or Api.UpdateShort
// (.update) -- so a top-level `instanceof UpdateNewAuthorization` check misses it and
// the INSTANT push is silently dropped, leaving only the slow periodic sweep. The
// high-level client unwraps these; we must too. We unwrap ONE level (these containers
// are not nested) and still act ONLY on UpdateNewAuthorization -- every other inner
// update (messages, etc.) is ignored, preserving the single-branch reader (spec 2.3).
export function unwrapUpdates(update) {
  if (!update) return [];
  if (update instanceof Api.Updates || update instanceof Api.UpdatesCombined) return update.updates ?? [];
  if (update instanceof Api.UpdateShort) return update.update ? [update.update] : [];
  return [update]; // a bare update (incl. UpdateNewAuthorization itself), or a type we ignore
}

// processEntities neutralization (H-2, spec 4.4): non-self peer entities are
// never ingested on either the update or the RPC-result path. This is the
// no-op the gateway installs in place of GramJS's entity cache.
export function makeNoOpEntityCache() {
  return {
    add() { /* no-op: message-update peer entities are never cached */ },
    get() { return undefined; },
    // The encoder may serialize ONLY {dc_id, server_address, port, auth_key} at
    // the onboarding RECOVERY/FINAL checkpoints; no armed path can call save().
    save() { throw new Error("entity/session save is disabled on armed connections (H-2)"); },
  };
}

// Build an armed transport over a connected GramJS sender. The raw connection +
// authenticator are injected (`conn`) so the live socket lives in the forked
// connection package whose two write sites CI censuses; this factory wires the
// chokepoint, the audited serialization, the keepalive, and the update filter.
//
// conn contract (implemented by the forked connection package in the EIF):
//   conn.sender            : MTProtoSender (owns _sendQueue)
//   conn.connect()         : performs WRITE SITE 1 handshake + bring-up
//   conn.disconnect()
//   conn.invoke(request)   : sends via the audited sender, returns the result
//   conn.onUpdate(cb)      : registers the raw handler (we attach filterUpdate)
//   conn.migrateDc(dcId)   : export/import auth across DCs (chokepoint-gated)
//   conn.chokepoint        : the bound chokepoint (connection.mjs owns it and
//                            installs the audited serialization; the transport
//                            does NOT re-install, only consumes).
export async function makeArmedTransport({ conn, onNewAuth }) {
  if (!conn.chokepoint || conn.chokepoint.mode !== MODES.ARMED) throw new Error("armed transport requires an ARMED connection");

  conn.onUpdate((u) => {
    // Unwrap the standard update container (the instant new-login push arrives wrapped),
    // then read ONLY UpdateNewAuthorization from the inner updates.
    for (const inner of unwrapUpdates(u)) {
      const evt = filterUpdate(inner);
      if (evt && typeof onNewAuth === "function") onNewAuth(evt);
    }
  });

  let keepalive = null;
  const startKeepalive = () => {
    keepalive = setInterval(() => {
      conn.invoke(new Api.updates.GetState()).catch(() => { /* reconnect loop handles it */ });
    }, KEEPALIVE_MS);
    if (keepalive.unref) keepalive.unref();
  };

  return {
    sender: conn.sender,
    connect: async () => {
      await conn.connect();
      // Subscribe to the update stream so Telegram pushes UpdateNewAuthorization in real
      // time. The high-level client did this on connect; the minimal client must too, or
      // the server may not push new-login updates and detection falls back to the slow
      // periodic sweep. updates.getState is allowlisted; failure is non-fatal (the sweep
      // is the authoritative fallback detector).
      try { await conn.invoke(new Api.updates.GetState()); } catch { /* sweep covers it */ }
      startKeepalive();
    },
    disconnect: async () => { if (keepalive) clearInterval(keepalive); await conn.disconnect(); },
    whoAmI: async () => {
      const res = await conn.invoke(new Api.users.GetUsers({ id: [new Api.InputUserSelf()] }));
      const me = Array.isArray(res) ? res[0] : res;
      return { tgUserId: String(me.id) }; // binding-2 source; only .id is used
    },
    listSessions: async () => {
      const res = await conn.invoke(new Api.account.GetAuthorizations());
      return (res.authorizations ?? []).map(publicAuthFields);
    },
    readSecurityState: async () => {
      const pwd = await conn.invoke(new Api.account.GetPassword());
      const ttl = await conn.invoke(new Api.account.GetAccountTTL());
      return {
        hasPwd: !!pwd.hasPassword,
        hasRecovery: !!pwd.hasRecovery,
        pendingReset: !!pwd.pendingResetDate,
        pendingResetAt: pwd.pendingResetDate ? Number(pwd.pendingResetDate) : undefined,
        loginEmailPattern: pwd.loginEmailPattern ?? undefined,
        accountTtlDays: ttl?.days ?? null,
        sessionTtlDays: pwd.sessionTtlDays ?? null,
      };
    },
    evictSession: async (hash, extraHooks) => {
      // Bind the policy-approved hash on the chokepoint so the AUTHORITATIVE
      // audited seam (audited-sender, which validates WITHOUT per-call hooks) — not
      // just the API-layer invoke — authorizes exactly this ResetAuthorization. The
      // seam re-checks the request hash == the bound hash, then it is cleared. (The
      // per-call extraHooks gate is kept as belt-and-suspenders for the API layer.)
      conn.chokepoint.bindEvict(hash);
      try {
        await conn.invoke(new Api.account.ResetAuthorization({ hash: BigInt(hash) }), extraHooks);
      } finally {
        conn.chokepoint.bindEvict(null);
      }
      return true;
    },
    declineReset: async () => { await conn.invoke(new Api.account.DeclinePasswordReset()); return true; },
    logOutSelf: async () => {
      try { await conn.invoke(new Api.auth.LogOut()); return true; }
      catch { return true; } // a dead/invalid session is also "gone"
    },
  };
}

// Exactly the public account.Authorization fields (spec 4.7 SessionRow). No
// auth_key, no session string.
function publicAuthFields(a) {
  return {
    hash: String(a.hash), current: !!a.current, unconfirmed: !!a.unconfirmed,
    deviceModel: a.deviceModel ?? null, platform: a.platform ?? null, systemVersion: a.systemVersion ?? null,
    appName: a.appName ?? null, appVersion: a.appVersion ?? null,
    ip: a.ip ?? null, country: a.country ?? null, region: a.region ?? null,
    dateCreated: a.dateCreated ?? null, dateActive: a.dateActive ?? null,
  };
}

export { KEEPALIVE_MS, publicAuthFields };
