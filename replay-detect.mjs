// gateway/replay-detect.mjs: the tdata-REPLAY detector (docs/tdata-replay-detection
// -gameplan.md §4). A tdata copy reuses the victim's auth_key, so Telegram reports
// it as the SAME authorization / SAME hash: no new-login event, no notification,
// invisible in the victim's own device list. The ONLY surface is account.get-
// Authorizations, where the shared hash's reported city + device model follow
// whoever is currently connecting. We watch that roster and classify the contested
// session by its IMPOSSIBLE MOVEMENT.
//
// This module is PURE LOGIC (no I/O, no clock of its own): classifyReplay takes the
// roster, a geo-state object, and `now`, mutates the geo-state in place (ring push +
// baseline seed + teleport streak), and returns the verdicts. The gateway owns the
// side effects (emit replay_suspected, set ctx.fastUntil, in P3 propose the burn).
// Keeping it pure makes the golden-sequence unit test (tests/replay-detect.test.ts)
// replay a real capture deterministically.
//
// Geo is CITY-LEVEL ONLY by design: account.getAuthorizations redacts `ip` and
// `region` to "" for non-official apps (Appendix B), so the `country` field actually
// carries a "City, Country" string (e.g. "Baltimore, United States"). No ASN, no
// coordinates, so detection is SET-MEMBERSHIP only (no impossible-travel velocity).

export const DETECT_DEFAULTS = Object.freeze({
  W_FLAP_MS: 180_000,        // D7: flap observation window
  MIN_TRANSITIONS: 3,        // D7: country changes within the window
  MIN_DISTINCT_COUNTRIES: 2, // D7: country-level (a single VPN drop+reconnect is one A->B->A round-trip, < this)
  RING_N: 64,                // per-hash observation ring
  LIVE_WINDOW_MS: 10_000,    // dateActive must be this recent to count as a LIVE observation
  TELEPORT_MIN_POLLS: 2,     // teleport must persist this many consecutive live polls before T3 (anti-jitter)
  // Passive baseline widening is OFF by default. The gameplan calls for widening the
  // home-set passively over 24-48h to reduce false positives for travelers, but an
  // over-eager widen would ABSORB a sustained attacker's city as "home" and silence
  // the very teleport we exist to catch (the same hazard as the selfFence re-seed,
  // §4). In auto_burn the burn lands within one sweep so widening never gets the
  // chance; under alert-only it would. We therefore widen ONLY from the SIGNED
  // allowlist (P2) and the explicit enrollment seeding (P2 operator script). Leave
  // this false until a widen guard that excludes contested localities exists (P5/v1).
  ALLOW_PASSIVE_WIDEN: false,
});

// "Baltimore, United States" -> "United States". The locality string is
// "City, Country"; the country is the last comma-delimited segment.
export function countryOf(locality) {
  if (!locality) return "";
  const i = locality.lastIndexOf(",");
  return (i === -1 ? locality : locality.slice(i + 1)).trim();
}

export function makeGeoState() {
  return {
    // hash -> [{ locality, country, deviceModel, dateActive, at, live }] (most recent last)
    ring: new Map(),
    // hash -> { homeKeys:Set<locality>, knownDevices:Set<device>, bornAt:number, seeded:boolean }
    baseline: new Map(),
    // hash -> { locality, count } consecutive out-of-baseline LIVE observations
    pendingTeleport: new Map(),
  };
}

// A session is LIVE this observation if its dateActive (unix seconds) is recent.
// An idle session whose roster geo went stale must NEVER fire (the original false
// negative): we require provable current activity, not just a changed label.
function isLive(dateActive, now, windowMs) {
  if (dateActive == null) return false;
  const ms = Number(dateActive) * 1000;
  if (!Number.isFinite(ms)) return false;
  return now - ms <= windowMs && now - ms >= -windowMs; // tolerate small clock skew
}

// Count country transitions + distinct countries among the LIVE ring entries inside
// the flap window. Only live observations count, so one live pole + one stale/cached
// pole is NOT a flap (both ends must be provably live).
function flapStats(entries, now, p) {
  const live = entries.filter((e) => e.live && now - e.at <= p.W_FLAP_MS);
  let transitions = 0;
  const countries = new Set();
  let prev = null;
  for (const e of live) {
    countries.add(e.country);
    if (prev !== null && e.country !== prev) transitions += 1;
    prev = e.country;
  }
  return { transitions, countries: [...countries] };
}

// classifyReplay(sessions, geoState, now, params) -> ReplayVerdict[]
//
// ReplayVerdict = {
//   hash, tier: 1|2|3, trigger: "advisory"|"flap"|"teleport",
//   locality, signals: { live, flap?, teleport?, deviceChanged? }
// }
//
// Side effect: mutates geoState (ring/baseline/pendingTeleport). Prunes state for
// hashes no longer in the roster. Returns one verdict per hash that changed location
// or looks contested; an empty array means nothing to report.
export function classifyReplay(sessions, geoState, now, params = {}) {
  const p = { ...DETECT_DEFAULTS, ...params };
  const { ring, baseline, pendingTeleport } = geoState;
  const verdicts = [];
  const seenHashes = new Set();

  for (const s of sessions ?? []) {
    const hash = String(s.hash);
    // Fire only on a NON-current, real session. hash "0" is the guard's own row;
    // !current already excludes it (belt-and-suspenders).
    if (s.current || hash === "0") continue;
    seenHashes.add(hash);

    const locality = s.country ?? null; // "City, Country" string (Telegram's redacted geo)
    const country = countryOf(locality);
    const live = isLive(s.dateActive, now, p.LIVE_WINDOW_MS);
    const device = s.deviceModel ?? null;

    const hist = ring.get(hash);
    const prevEntry = hist && hist.length ? hist[hist.length - 1] : null;
    const prevLocality = prevEntry ? prevEntry.locality : null;

    // First time we have ever seen this hash: SEED its baseline (its current home)
    // and record it. Never classify on the seeding observation (that is just learning
    // the home, D9), so a freshly-enrolled device never self-flags.
    if (!baseline.has(hash)) {
      baseline.set(hash, {
        homeKeys: new Set(locality ? [locality] : []),
        knownDevices: new Set(device ? [device] : []),
        bornAt: now,
        seeded: true,
      });
      pushRing(ring, hash, { locality, country, deviceModel: device, dateActive: s.dateActive ?? null, at: now, live }, p);
      continue;
    }

    const base = baseline.get(hash);
    const inBaseline = locality != null && base.homeKeys.has(locality);
    // deviceChanged is a CORROBORATOR ONLY (never a standalone trigger): true when the
    // current device model is not one we have seen for this hash before this poll
    // (computed against the ring BEFORE we record the current device below).
    const corroboratedDeviceChange = device != null && !prevEntryDeviceSeen(hist, device);
    base.knownDevices.add(device ?? "");

    // Push the observation BEFORE running flap (flap reads the ring including now).
    pushRing(ring, hash, { locality, country, deviceModel: device, dateActive: s.dateActive ?? null, at: now, live }, p);

    // TRIGGER A — FLAP (D7): country oscillation across >= MIN_DISTINCT_COUNTRIES
    // within W_FLAP, both poles provably live. ALWAYS T3 (no toggle relaxes it, no
    // fresh-window suppression). No benign single-hash instance exists.
    const fs = flapStats(ring.get(hash), now, p);
    if (live && fs.transitions >= p.MIN_TRANSITIONS && fs.countries.length >= p.MIN_DISTINCT_COUNTRIES) {
      pendingTeleport.delete(hash);
      verdicts.push({
        hash, tier: 3, trigger: "flap", locality,
        signals: { live, deviceChanged: corroboratedDeviceChange, flap: { transitions: fs.transitions, countries: fs.countries, windowMs: p.W_FLAP_MS } },
      });
      continue;
    }

    // TRIGGER B — TELEPORT: a baseline EXISTS and the current City,Country is outside
    // it, persisting >= TELEPORT_MIN_POLLS consecutive LIVE polls (anti-jitter), gated
    // on baseline-PRESENCE not a timer (D8). First suspicious poll -> T2 (arm fast-poll);
    // the confirming poll -> T3 (burn-eligible in P3).
    if (live && locality != null && !inBaseline) {
      const streak = pendingTeleport.get(hash);
      const count = streak && streak.locality === locality ? streak.count + 1 : 1;
      pendingTeleport.set(hash, { locality, count });
      // HIGH-CONFIDENCE FAST PATH: a cross-COUNTRY teleport WITH a device-model change has no
      // benign single-poll explanation -- you cannot change country AND machine in one poll. So
      // burn on the FIRST poll, skipping the 2-poll persistence wait, landing the contested burn
      // ~1 poll after the attacker connects. The persistence guard (the false-positive buffer) is
      // KEPT for the ambiguous cases: same-country city jitter, metro-IP drift, or first travel to
      // a new city in the SAME country, or a move with no device change, still require 2 polls.
      const baseCountries = new Set([...base.homeKeys].map(countryOf));
      const crossCountry = !baseCountries.has(country);
      const highConfidence = crossCountry && corroboratedDeviceChange;
      const tier = (highConfidence || count >= p.TELEPORT_MIN_POLLS) ? 3 : 2;
      verdicts.push({
        hash, tier, trigger: "teleport", locality,
        signals: { live, deviceChanged: corroboratedDeviceChange, crossCountry, fastPath: highConfidence, teleport: { current: locality, baseline: [...base.homeKeys], persistedPolls: count } },
      });
      continue;
    }

    // Back in (or never left) the baseline: the teleport streak is broken.
    pendingTeleport.delete(hash);
    if (p.ALLOW_PASSIVE_WIDEN && live && locality != null) base.homeKeys.add(locality);

    // TRIGGER (advisory) — a benign location change among baseline/known localities, or
    // a not-yet-live change. T1 only: this is what upgrades the existing
    // session_location_changed notice; it never escalates on its own.
    if (prevLocality != null && prevLocality !== locality && locality != null) {
      verdicts.push({
        hash, tier: 1, trigger: "advisory", locality,
        signals: { live, deviceChanged: corroboratedDeviceChange },
      });
    }
  }

  // Prune state for hashes that left the roster (the gameplan: prune geoRing/geoBaseline
  // for hashes no longer present). Keeps the maps bounded across a busy account.
  for (const m of [ring, baseline, pendingTeleport]) {
    for (const h of m.keys()) if (!seenHashes.has(h)) m.delete(h);
  }

  return verdicts;
}

function pushRing(ring, hash, entry, p) {
  let arr = ring.get(hash);
  if (!arr) { arr = []; ring.set(hash, arr); }
  arr.push(entry);
  if (arr.length > p.RING_N) arr.splice(0, arr.length - p.RING_N);
}

// Was this device model seen in the hash's ring BEFORE the current observation?
// (Called before the current entry's device is treated as known.)
function prevEntryDeviceSeen(hist, device) {
  if (device == null) return true; // no device info -> never flag a change
  if (!hist) return false;
  for (const e of hist) if (e.deviceModel === device) return true;
  return false;
}
