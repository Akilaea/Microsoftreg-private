import argparse
import json
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

import websocket


KEYWORDS = [
    "outlook.live.com",
    "signup.live.com",
    "login.microsoftonline.com",
    "login.live.com",
    "account.live.com",
    "client.hip.live.com",
    "fpt.live.com",
    "df.cfp.microsoft.com",
    "iframe.hsprotect.net",
    "captcha.hsprotect.net",
    "client.hsprotect.net",
    "collector-pxzc5j78di.hsprotect.net",
    "stk.hsprotect.net",
    "hsprotect.net",
    "browser.events.data.microsoft.com",
]

BODY_KEYWORDS = [
    "collector-pxzc5j78di.hsprotect.net",
    "signup.live.com/API/CreateAccount",
    "signup.live.com/API/CheckAvailableSigninNames",
    "risk/verify",
    "risk/initialize",
    "api/v1.0/risk",
]


def now_iso():
    return datetime.now().isoformat()


def bounded(text, n=1_000_000):
    if text is None:
        return None
    if len(text) <= n:
        return text
    return text[:n] + f"\n<truncated {len(text) - n} chars>"


def want(url: str) -> bool:
    return any(k in (url or "") for k in KEYWORDS)


def want_body(url: str) -> bool:
    return any(k in (url or "") for k in BODY_KEYWORDS)


class BrowserCDPObserver:
    def __init__(self, endpoint: str, out: Path, timeout_seconds: int):
        self.endpoint = endpoint.rstrip("/")
        self.out = out
        self.stop_at = time.time() + max(1, timeout_seconds)
        self.ws = None
        self.next_id = 0
        self.lock = threading.Lock()
        self.pending = {}
        self.sessions = {}
        self.attached_targets = set()
        self.requests = {}
        self.pending_responses = {}

    def write(self, obj):
        self.out.parent.mkdir(parents=True, exist_ok=True)
        with self.out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")

    def browser_ws_url(self) -> str:
        with urllib.request.urlopen(self.endpoint + "/json/version", timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        return data["webSocketDebuggerUrl"]

    def send(self, method, params=None, session_id=None, action=None):
        with self.lock:
            self.next_id += 1
            mid = self.next_id
            msg = {"id": mid, "method": method, "params": params or {}}
            if session_id:
                msg["sessionId"] = session_id
            self.pending[mid] = {"action": action, "method": method, "sessionId": session_id}
            self.ws.send(json.dumps(msg))
            return mid

    def attach_target(self, target_info):
        tid = target_info.get("targetId")
        if not tid or tid in self.attached_targets:
            return
        typ = target_info.get("type") or ""
        url = target_info.get("url") or ""
        if typ not in ("page", "iframe", "worker", "shared_worker", "service_worker"):
            return
        if typ != "page" and not want(url):
            return
        self.attached_targets.add(tid)
        self.send("Target.attachToTarget", {"targetId": tid, "flatten": True}, action=("attach", target_info))

    def poll_targets(self):
        self.send("Target.getTargets", action=("getTargets", None))

    def enable_session(self, session_id, target_info):
        self.sessions[session_id] = target_info or {}
        print(
            f"[BrowserCDP] attach session={session_id} type={target_info.get('type')} "
            f"title={target_info.get('title')} url={target_info.get('url')}",
            flush=True,
        )
        self.send("Network.enable", {}, session_id=session_id, action=("enable", None))

    def handle_command_response(self, msg):
        mid = msg.get("id")
        item = self.pending.pop(mid, None)
        if not item:
            return
        action = item.get("action")
        if not action:
            return
        kind, payload = action
        if kind == "getTargets":
            for t in ((msg.get("result") or {}).get("targetInfos") or []):
                self.attach_target(t)
        elif kind == "attach":
            sid = ((msg.get("result") or {}).get("sessionId"))
            if sid:
                self.enable_session(sid, payload or {})
        elif kind == "getBody":
            rec = payload
            result = msg.get("result") or {}
            if "error" in msg:
                rec["body_error"] = json.dumps(msg.get("error"), ensure_ascii=False)[:240]
            elif result.get("base64Encoded"):
                rec["body_base64"] = bounded(result.get("body") or "")
            else:
                rec["body"] = bounded(result.get("body") or "")
            self.write(rec)
            self.print_decisive(rec)

    def target_meta(self, session_id):
        t = self.sessions.get(session_id) or {}
        return {
            "target_type": t.get("type"),
            "target_url": t.get("url"),
            "target_title": t.get("title"),
        }

    def handle_event(self, msg):
        method = msg.get("method") or ""
        params = msg.get("params") or {}
        sid = msg.get("sessionId")
        if method == "Target.attachedToTarget":
            p_sid = params.get("sessionId")
            target_info = params.get("targetInfo") or {}
            if p_sid:
                self.attached_targets.add(target_info.get("targetId"))
                self.enable_session(p_sid, target_info)
            return
        if method == "Target.targetCreated":
            self.attach_target(params.get("targetInfo") or {})
            return
        if not sid:
            return
        if method == "Network.requestWillBeSent":
            self.on_request(sid, params)
        elif method == "Network.responseReceived":
            self.on_response(sid, params)
        elif method == "Network.loadingFinished":
            self.on_loading_finished(sid, params)
        elif method == "Network.loadingFailed":
            self.on_loading_failed(sid, params)

    def on_request(self, sid, params):
        req = params.get("request") or {}
        url = req.get("url") or ""
        rid = params.get("requestId")
        self.requests[(sid, rid)] = {"method": req.get("method"), "url": url}
        if not want(url):
            return
        rec = {
            "ts": now_iso(),
            "event": "request",
            "session_id": sid,
            "method": req.get("method"),
            "url": url,
            "resource_type": (params.get("type") or "").lower(),
            "headers": req.get("headers") or {},
            **self.target_meta(sid),
        }
        if req.get("postData") is not None:
            rec["post_data"] = bounded(req.get("postData"))
        self.write(rec)

    def on_response(self, sid, params):
        resp = params.get("response") or {}
        url = resp.get("url") or ""
        if not want(url):
            return
        rid = params.get("requestId")
        req = self.requests.get((sid, rid), {})
        rec = {
            "ts": now_iso(),
            "event": "response",
            "session_id": sid,
            "method": req.get("method", ""),
            "url": url,
            "status": resp.get("status"),
            "headers": resp.get("headers") or {},
            **self.target_meta(sid),
        }
        if want_body(url):
            self.pending_responses[(sid, rid)] = rec
        else:
            self.write(rec)

    def on_loading_finished(self, sid, params):
        rid = params.get("requestId")
        rec = self.pending_responses.pop((sid, rid), None)
        if not rec:
            return
        self.send("Network.getResponseBody", {"requestId": rid}, session_id=sid, action=("getBody", rec))

    def on_loading_failed(self, sid, params):
        rid = params.get("requestId")
        rec = self.pending_responses.pop((sid, rid), None)
        if not rec:
            return
        rec["body_error"] = f"loadingFailed:{params.get('errorText')}"
        self.write(rec)

    @staticmethod
    def print_decisive(rec):
        url = rec.get("url") or ""
        if "signup.live.com/API/CreateAccount" in url:
            body = rec.get("body") or ""
            code = error = server_error = ""
            try:
                parsed = json.loads(body) if body else {}
                code = str(parsed.get("errorCode") or parsed.get("code") or "")
                error = str(parsed.get("error") or parsed.get("errorDescription") or parsed.get("message") or "")
                server_error = str(parsed.get("server_error") or parsed.get("serverError") or "")
            except Exception:
                if "server_error" in body:
                    server_error = "present"
                if "contextID" in body or "matching cookie" in body:
                    error = "contextID cookie mismatch"
            print(
                f"[BrowserCDP] CreateAccount status={rec.get('status')} "
                f"code={code or '-'} server_error={server_error or '-'} "
                f"error={(error[:120] if error else '-')}",
                flush=True,
            )
        if "api/v1.0/risk/verify" in url:
            body = rec.get("body") or ""
            state = err_code = inner_code = ""
            try:
                parsed = json.loads(body) if body else {}
                state = parsed.get("state") or ""
                err = parsed.get("error") or {}
                err_code = err.get("code") or ""
                inner_code = (err.get("innerError") or {}).get("code") or ""
            except Exception:
                pass
            print(
                f"[BrowserCDP] risk/verify status={rec.get('status')} "
                f"state={state or '-'} err={err_code or '-'} inner={inner_code or '-'}",
                flush=True,
            )
        if "collector-pxzc5j78di.hsprotect.net" in url:
            body = str(rec.get("body") or rec.get("body_base64") or "")
            score = ""
            if "IoIoIo|score|" in body:
                score = body.split("IoIoIo|score|", 1)[1].split("|", 1)[0][:8]
            print(f"[BrowserCDP] collector status={rec.get('status')} score={score or '-'} url={url}", flush=True)

    def run(self):
        print(f"[BrowserCDP] network log: {self.out.resolve()}", flush=True)
        self.ws = websocket.create_connection(self.browser_ws_url(), timeout=5, suppress_origin=True)
        self.ws.settimeout(1.0)
        self.send("Target.setDiscoverTargets", {"discover": True}, action=("discover", None))
        self.send(
            "Target.setAutoAttach",
            {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True},
            action=("autoAttach", None),
        )
        next_poll = 0
        while time.time() < self.stop_at:
            if time.time() >= next_poll:
                self.poll_targets()
                next_poll = time.time() + 2.0
            try:
                msg = json.loads(self.ws.recv())
            except websocket.WebSocketTimeoutException:
                continue
            except Exception as exc:
                print(f"[BrowserCDP] recv end: {exc!r}", flush=True)
                break
            if "id" in msg:
                self.handle_command_response(msg)
            else:
                self.handle_event(msg)
        print("[BrowserCDP] done", flush=True)


def main():
    ap = argparse.ArgumentParser(description="Browser-level CDP observer that captures page + OOPIF iframe network.")
    ap.add_argument("--cdp-endpoint", default="http://127.0.0.1:19222")
    ap.add_argument("--timeout-seconds", type=int, default=600)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    BrowserCDPObserver(args.cdp_endpoint, Path(args.out), args.timeout_seconds).run()


if __name__ == "__main__":
    main()
