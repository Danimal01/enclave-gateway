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

// The client-IDENTITY tuple (spec v2 §4 Tier B). A change in ANY of these four
// fields means a DIFFERENT machine/client is driving the auth_key. system_version /
// app_version are DELIBERATELY EXCLUDED (a benign OS/app update bumps them and can
// coincide with travel) -- versions are advisory only, never a burn trigger.
export function fingerprintOf(s) {
  return {
    deviceModel: s.deviceModel ?? null,
    platform: s.platform ?? null,
    apiId: s.apiId ?? null,
    officialApp: s.officialApp ?? null,
  };
}

// True if the LIVE identity differs from the ENROLLED identity in any of the four
// fields. Anchored to the enrolled fingerprint, never the prior poll: a desktop hash
// that starts reporting platform=iOS is an identity change (the anti-dodge, §4 / §8.2),
// not a new normal. Only fields the enrolled baseline actually captured are compared
// (a null enrolled field never manufactures a change from a transient null read).
export function identityChanged(enrolled, current) {
  if (!enrolled) return false; // no baseline captured yet -> cannot be a change
  for (const k of ["deviceModel", "platform", "apiId", "officialApp"]) {
    const e = enrolled[k] ?? null;
    const c = current[k] ?? null;
    if (e != null && c != null && String(e) !== String(c)) return true;
  }
  return false;
}

// Route a Telegram `platform` string to the policy class that decides Tier C handling
// (desktop = burn on untrusted teleport; mobile = alert only). Real clients always
// report a platform; an unknown/blank value routes to DESKTOP by decision (the
// documented tdata threat surface; matches v1 which burned all teleports).
export function platformClass(platform) {
  return /android|ios|iphone|ipad/i.test(String(platform ?? "")) ? "mobile" : "desktop";
}

export function makeGeoState() {
  return {
    // hash -> [{ locality, country, deviceModel, dateActive, at, live }] (most recent last)
    ring: new Map(),
    // hash -> { homeKeys:Set<locality>, knownDevices:Set<device>, bornAt:number,
    //           seeded:boolean, enrolledFp:{deviceModel,platform,apiId,officialApp},
    //           enrolledPlatform:"desktop"|"mobile" }
    // enrolledFp/enrolledPlatform are captured ONCE at first-sight and never overwritten
    // (the §6 invariant: identity policy follows the ENROLLED value, never the live poll).
    baseline: new Map(),
    // hash -> { locality, count } consecutive out-of-baseline LIVE observations
    pendingTeleport: new Map(),
    // Recovery / re-seed window flag (§5.2, §6). When the gateway sets this true (during
    // a baseline rebuild / recovery), classifyReplay still seeds + rings but CAPS every
    // verdict at alert (tier 2) so a baseline freshly (re)built mid-attack can never burn
    // before the operator/recovery flow corrects it. Set BY REFERENCE on the geoState the
    // gateway owns; survives the selfFence stash with the rest of geoState. Default off.
    // NOTE (intentionally inert today): no production path sets this true yet. The baseline
    // survives selfFence (stashed in _geoByHandle), so a fence does NOT re-seed, and recovery
    // re-enroll mints a NEW hash seeded at the real re-login city. This is a ready seam for a
    // future explicit re-baseline path; arm it (ctx.geo.reseedHold = true) when one lands.
    reseedHold: false,
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
//   hash, tier: 1|2|3, tierClass: "A"|"B"|"C" (omitted for advisory),
//   trigger: "advisory"|"flap"|"teleport", locality,
//   platform: "desktop"|"mobile" (the ENROLLED routing class; set on flap/teleport),
//   signals: { live, identityChanged?, deviceChanged?, crossCountry?, fastPath?, flap?, teleport? }
// }
//
// The §4 ladder (precedence A > B > C): Tier A = flap (always burns, both platforms);
// Tier B = teleport WITH a client-IDENTITY change (burns both platforms, first poll);
// Tier C = same-identity teleport (the ambiguous geo case). The detector reports the tier
// + the ENROLLED platform; the burn/allowlist ROUTING lives in the gate (P3): desktop
// Tier C burns, mobile Tier C alerts, and the signed allowlist relaxes ONLY Tier C.
//
// Side effect: mutates geoState (ring/baseline/pendingTeleport). Prunes state for
// hashes no longer in the roster. Returns one verdict per hash that changed location
// or looks contested; an empty array means nothing to report.
export function classifyReplay(sessions, geoState, now, params = {}) {
  const p = { ...DETECT_DEFAULTS, ...params };
  const { ring, baseline, pendingTeleport } = geoState;
  // Recovery / re-seed window (§5.2/§6): cap every verdict at alert (tier 2) so a baseline
  // (re)built mid-attack can never burn before the operator/recovery flow corrects it.
  const reseedHold = !!geoState.reseedHold;
  const cap = (tier) => (reseedHold ? Math.min(tier, 2) : tier);
  // The ACTIVE signed trusted-locations allowlist (v2 §4), resolved by the brain (permanent
  // entries always; time-boxed only while travel_mode is on and unexpired). A Set of strings,
  // each a whole-country wildcard ("United States") or a precise "City, Country". Relaxes ONLY
  // Tier C; Tier A (flap) and Tier B (identity change) never consult it.
  const activeAllowlist = p.activeAllowlist instanceof Set ? p.activeAllowlist : null;
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
    const fp = fingerprintOf(s);

    const hist = ring.get(hash);
    const prevEntry = hist && hist.length ? hist[hist.length - 1] : null;
    const prevLocality = prevEntry ? prevEntry.locality : null;

    // First time we have ever seen this hash: SEED its baseline (its current home AND its
    // enrolled client-identity) and record it. Never classify on the seeding observation
    // (that is just learning the home, D9), so a freshly-enrolled device never self-flags.
    // enrolledFp/enrolledPlatform are captured ONCE here and never overwritten (§6).
    if (!baseline.has(hash)) {
      baseline.set(hash, {
        homeKeys: new Set(locality ? [locality] : []),
        knownDevices: new Set(device ? [device] : []),
        bornAt: now,
        seeded: true,
        enrolledFp: fp,
        enrolledPlatform: platformClass(fp.platform),
      });
      pushRing(ring, hash, { locality, country, deviceModel: device, dateActive: s.dateActive ?? null, at: now, live }, p);
      continue;
    }

    const base = baseline.get(hash);
    // Back-compat fill for a baseline seeded by a pre-v2 build (no enrolledFp): capture it
    // from the current row ONCE. This is a fill of a missing value, never a re-seed of an
    // existing one (which would violate §6's enrolled-identity invariant).
    if (!base.enrolledFp) { base.enrolledFp = fp; base.enrolledPlatform = platformClass(fp.platform); }
    const platform = base.enrolledPlatform;
    const inBaseline = locality != null && base.homeKeys.has(locality);
    // IDENTITY change vs the ENROLLED fingerprint (Tier B): a different machine/client is
    // driving the key (device_model / platform / api_id / official_app). deviceChanged
    // (device_model vs the ring) is kept as an advisory corroborator signal only.
    const idChanged = identityChanged(base.enrolledFp, fp);
    const corroboratedDeviceChange = device != null && !prevEntryDeviceSeen(hist, device);
    base.knownDevices.add(device ?? "");

    // Push the observation BEFORE running flap (flap reads the ring including now).
    pushRing(ring, hash, { locality, country, deviceModel: device, dateActive: s.dateActive ?? null, at: now, live }, p);

    // TIER A — FLAP (D7): country oscillation across >= MIN_DISTINCT_COUNTRIES within
    // W_FLAP, both poles provably live. Burns BOTH platforms; no toggle/allowlist relaxes
    // it, no fresh-window suppression. No benign single-hash instance exists.
    const fs = flapStats(ring.get(hash), now, p);
    if (live && fs.transitions >= p.MIN_TRANSITIONS && fs.countries.length >= p.MIN_DISTINCT_COUNTRIES) {
      pendingTeleport.delete(hash);
      verdicts.push({
        hash, tier: cap(3), tierClass: "A", trigger: "flap", locality, platform,
        signals: { live, identityChanged: idChanged, deviceChanged: corroboratedDeviceChange, flap: { transitions: fs.transitions, countries: fs.countries, windowMs: p.W_FLAP_MS } },
      });
      continue;
    }

    // TELEPORT: a baseline EXISTS and the current City,Country is outside it, live, gated
    // on baseline-PRESENCE not a timer (D8).
    if (live && locality != null && !inBaseline) {
      const baseCountries = new Set([...base.homeKeys].map(countryOf));
      const crossCountry = !baseCountries.has(country);

      // TIER B — teleport WITH a client-IDENTITY change. A different machine/client AND a
      // moved location has no benign single-poll explanation -> burn on the FIRST poll
      // (both platforms), skipping the persistence buffer. Clear any same-identity streak.
      if (idChanged) {
        pendingTeleport.delete(hash);
        verdicts.push({
          hash, tier: cap(3), tierClass: "B", trigger: "teleport", locality, platform,
          signals: { live, identityChanged: true, deviceChanged: corroboratedDeviceChange, crossCountry, fastPath: true, teleport: { current: locality, baseline: [...base.homeKeys], persistedPolls: 1 } },
        });
        continue;
      }

      // ALLOWLIST (v2 §4): a same-identity teleport into an ACTIVE trusted locality is allowed
      // SILENTLY (no verdict). Match a precise "City, Country" entry exactly OR a whole-country
      // wildcard. This relaxes ONLY Tier C -- Tier A/B above already returned.
      if (activeAllowlist && (activeAllowlist.has(locality) || activeAllowlist.has(country))) {
        pendingTeleport.delete(hash);
        continue;
      }

      // TIER C — same-identity teleport (the ambiguous geo case). Keep the v1 anti-jitter
      // buffer: require >= TELEPORT_MIN_POLLS consecutive LIVE polls in the SAME locality
      // before T3 (absorbs same-country metro-IP drift / a single bad geo read). First poll
      // -> T2 (arm fast-poll). The P3 gate burns this for DESKTOP, alerts for MOBILE.
      const streak = pendingTeleport.get(hash);
      const count = streak && streak.locality === locality ? streak.count + 1 : 1;
      pendingTeleport.set(hash, { locality, count });
      const tier = count >= p.TELEPORT_MIN_POLLS ? 3 : 2;
      verdicts.push({
        hash, tier: cap(tier), tierClass: "C", trigger: "teleport", locality, platform,
        signals: { live, identityChanged: false, deviceChanged: corroboratedDeviceChange, crossCountry, fastPath: false, teleport: { current: locality, baseline: [...base.homeKeys], persistedPolls: count } },
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
        signals: { live, identityChanged: idChanged, deviceChanged: corroboratedDeviceChange },
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
