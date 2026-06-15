// gateway/audited-sender.mjs: the audited serialization boundary
// (gateway-brain-architecture.md 4.3 "H-1 refinement", H-8).
//
// Wrapping a single exported send() is NOT sufficient on stock GramJS: the base
// client also enqueues via addStateToQueue, and the send loop pulls
// RequestStates off _sendQueue and serializes them directly, so MsgsAck/Ping
// and bring-up frames never pass through send(). The gateway therefore audits
// the MessagePacker at TWO seams, which are the only paths to the wire:
//
//   1. append(state): the earliest point a RequestState enters the queue,
//      BEFORE writeDataAsMessage serializes it to bytes. assertAllowed runs on
//      the DECODED request (spec: "runs on the decoded request before
//      serialization or compression"), so gzip_packed below cannot smuggle.
//   2. get() -> {batch}: the dequeue that feeds directly into
//      _state.encryptMessageData. Every RequestState in the flushed batch
//      (including internally appended MsgsAck and each element of a container)
//      is individually re-validated.
//
// On a forbidden frame the gateway FAILS CLOSED: it rejects the offending
// request's promise and throws, so the connection emits no further bytes. A
// forbidden frame never occurs in correct operation; if one appears it is a bug
// or an attack, and stopping the wire is the safe response.
//
// This installs the audit on a constructed MTProtoSender instance rather than
// maintaining a full source fork, so it tracks the pinned GramJS build exactly
// (the lockfile pins the version). The published gateway ships this file plus
// the pinned dependency.

export function installAuditedSerialization(sender, chokepoint, { onViolation } = {}) {
  const packer = sender._sendQueue;
  if (!packer || typeof packer.append !== "function" || typeof packer.get !== "function") {
    throw new Error("audited-sender: unexpected sender shape (pinned GramJS build changed?)");
  }
  if (packer.__sessionsAudited) throw new Error("audited-sender: already installed");

  const validate = (request, where) => {
    try {
      chokepoint.assertAllowed(request);
    } catch (e) {
      const reason = `audited-sender(${where}): ${e.message}`;
      if (typeof onViolation === "function") { try { onViolation(reason, request); } catch { /* noop */ } }
      throw new Error(reason);
    }
  };

  const origAppend = packer.append.bind(packer);
  const origGet = packer.get.bind(packer);

  // Seam 1: validate at enqueue, before serialization.
  packer.append = function auditedAppend(state, setReady = true, atStart = false) {
    if (state && state.request) {
      try {
        validate(state.request, "append");
      } catch (e) {
        // Reject this request's own promise so the caller sees the refusal, and
        // do NOT enqueue it: a blocked frame never reaches the wire.
        try { state.promise?.reject?.(e); } catch { /* promise may be settled */ }
        throw e;
      }
    }
    return origAppend(state, setReady, atStart);
  };

  // Seam 2: re-validate every dequeued RequestState before encryptMessageData.
  packer.get = async function auditedGet() {
    const res = await origGet();
    if (res && res.batch) {
      for (const item of res.batch) {
        const states = Array.isArray(item) ? item : [item];
        for (const s of states) {
          if (s && s.request) validate(s.request, "serialize");
        }
      }
    }
    return res;
  };

  Object.defineProperty(packer, "__sessionsAudited", { value: true, enumerable: false });
  return sender;
}

// The set of internal frames the sender legitimately self-sends. The pinned
// build self-sends nothing outside this set; an unenumerated self-send is
// rejected at the audited seam, not passed silently (spec 4.3 self-sent set).
export const EXPECTED_SELF_SENT = Object.freeze(["MsgsAck", "Ping", "PingDelayDisconnect", "MsgsStateInfo"]);
