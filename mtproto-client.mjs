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
// Idle threshold: if the update stream goes quiet this long, force a getDifference to
// self-recover a connection that silently stopped receiving pushes (the spec's
// "no updates for 15 min -> getDifference" rule, tightened for fast new-login detection).
const IDLE_DIFF_MS = Number(process.env.GW_IDLE_DIFF_MS || 30000);

export async function makeArmedTransport({ conn, onNewAuth }) {
  if (!conn.chokepoint || conn.chokepoint.mode !== MODES.ARMED) throw new Error("armed transport requires an ARMED connection");

  // ── MTProto update state machine (core.telegram.org/api/updates), validated live
  // 2026-06-17 (experiments/newauth-updateloop.mjs: 11/11 new-logins caught, push
  // survived reconnect, getDifference newMessages=0). UpdateNewAuthorization carries NO
  // pts/qts (it is a bare update in an updateShort) so it is delivered ONLY as a live push
  // and is NOT durably recoverable from getDifference. To receive it reliably in real time
  // we keep the update stream HEALTHY like a real client (TDLib/MadelineProto): track
  // pts/qts/seq/date and, on a seq/pts GAP, on UpdatesTooLong, and on long idle, call
  // updates.getDifference to resync. getDifference's newMessages/newEncryptedMessages are
  // DISCARDED unread (single-branch reader, spec 2.3); only otherUpdates is read (measured
  // newMessages=0 with state kept current). The ~Ns account.getAuthorizations sweep
  // (gateway.mjs) is the DURABLE backstop for the rare push the healthy stream still drops.
  let _us = null;          // {pts,qts,date,seq}; advanced via getState seed + getDifference + inline pts/seq
  let _lastUpdate = 0;
  let _catching = false;
  const _seed = (s) => { if (s && typeof s.pts === "number") _us = { pts: s.pts, qts: s.qts ?? 0, date: s.date ?? 0, seq: s.seq ?? 0 }; };

  // Errors (FLOOD_WAIT/transient/401) PROPAGATE so the refreshUpdates caller shares the
  // gateway's flood backoff; the onUpdate callers ignore them (.catch) and the next
  // trigger + the getAuthorizations sweep retry. A persistent 401 (session terminated)
  // surfaces through the same path the gateway's other invokes do.
  async function _catchUp() {
    if (!_us || _catching) return;
    _catching = true;
    try {
      for (let i = 0; i < 20; i++) { // bound the slice walk; idle/gap/sweep retry anything left
        const diff = await conn.invoke(new Api.updates.GetDifference({ pts: _us.pts, qts: _us.qts, date: _us.date }));
        if (diff instanceof Api.updates.DifferenceEmpty) { _us.date = diff.date; _us.seq = diff.seq; break; }
        // Read ONLY otherUpdates. newMessages / newEncryptedMessages are DISCARDED unread.
        for (const u of diff.otherUpdates ?? []) { const evt = filterUpdate(u); if (evt && typeof onNewAuth === "function") onNewAuth(evt); }
        const s = diff.state || diff.intermediateState;
        if (s) _us = { pts: s.pts, qts: s.qts, date: s.date, seq: s.seq };
        if (diff instanceof Api.updates.Difference) break;
        if (diff instanceof Api.updates.DifferenceTooLong) { _us.pts = diff.pts; break; }
      }
    } finally { _catching = false; }
  }

  conn.onUpdate((u) => {
    _lastUpdate = Date.now();
    // UpdatesTooLong: the server deferred updates -> resync (this is the mode a naive client drops).
    if ((u?.className || u?.constructor?.name) === "UpdatesTooLong") { _catchUp().catch(() => {}); return; }
    // seq tracking + gap detection on the container (a gap is how a missed new-login surfaces).
    if (_us && (u instanceof Api.Updates || u instanceof Api.UpdatesCombined)) {
      const seqStart = (typeof u.seqStart === "number" ? u.seqStart : u.seq);
      if (typeof seqStart === "number" && seqStart > 0 && _us.seq + 1 < seqStart) _catchUp().catch(() => {});
      if (typeof u.seq === "number" && u.seq > 0) { _us.seq = u.seq; _us.date = u.date ?? _us.date; }
    } else if (_us && u instanceof Api.UpdateShort && typeof u.date === "number") {
      _us.date = u.date;
    }
    // pts tracking + gap detection on inner updates; read UpdateNewAuthorization inline (sub-second).
    for (const inner of unwrapUpdates(u)) {
      if (_us && typeof inner?.pts === "number") {
        if (typeof inner.ptsCount === "number" && _us.pts + inner.ptsCount < inner.pts) _catchUp().catch(() => {});
        else if (typeof inner.ptsCount === "number" && _us.pts + inner.ptsCount === inner.pts) _us.pts = inner.pts;
        else if (inner.pts > _us.pts) _us.pts = inner.pts;
      }
      const evt = filterUpdate(inner);
      if (evt && typeof onNewAuth === "function") onNewAuth(evt);
    }
  });

  return {
    sender: conn.sender,
    connect: async () => {
      await conn.connect();
      // Subscribe to the update stream so Telegram pushes UpdateNewAuthorization in real
      // time. The high-level client did this on connect; the minimal client must too, or
      // the server may not push new-login updates and detection falls back to the slow
      // periodic sweep. updates.getState is allowlisted; failure is non-fatal (the sweep
      // is the authoritative fallback detector). The channel is then kept WARM by the
      // gateway's flood-aware refreshUpdatesAll loop (REFRESH_UPDATES -> refreshUpdates
      // below), which re-issues updates.getState every ~12s: Telegram only keeps pushing
      // to an otherwise-quiet connection while it receives a content-request inside a
      // short (~30s, measured) window, so this is what makes new-login detection
      // real-time instead of sweep-bound. (Transport liveness is separate: connection.mjs
      // pings every 15s.)
      // Seed update state so getDifference can resync; this call also opens the push window.
      try { _seed(await conn.invoke(new Api.updates.GetState())); _lastUpdate = Date.now(); } catch { /* sweep covers it */ }
    },
    disconnect: async () => { await conn.disconnect(); },
    // Driven by the gateway's flood-aware warmth loop (~12s). updates.getState holds
    // Telegram's push window open; we do NOT advance our tracked state from it (that would
    // skip past unfetched updates). If the stream has gone quiet past the idle threshold we
    // force a getDifference so a connection that silently stopped pushing self-recovers.
    refreshUpdates: async () => {
      if (!_us) { try { _seed(await conn.invoke(new Api.updates.GetState())); _lastUpdate = Date.now(); } catch { return true; } }
      else { try { await conn.invoke(new Api.updates.GetState()); } catch { /* warmth best-effort */ } }
      if (_us && Date.now() - _lastUpdate > IDLE_DIFF_MS) { _lastUpdate = Date.now(); await _catchUp(); }
      return true;
    },
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
    apiId: a.apiId == null ? null : Number(a.apiId), officialApp: a.officialApp == null ? null : !!a.officialApp,
    ip: a.ip ?? null, country: a.country ?? null, region: a.region ?? null,
    dateCreated: a.dateCreated ?? null, dateActive: a.dateActive ?? null,
  };
}

export { publicAuthFields };
