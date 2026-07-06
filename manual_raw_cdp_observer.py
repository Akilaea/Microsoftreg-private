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
    "hcaptcha.com",
    "js.hcaptcha.com",
    "newassets.hcaptcha.com",
    "api.hcaptcha.com",
    "imgs.hcaptcha.com",
    "iframe.hsprotect.net",
    "captcha.hsprotect.net",
    "client.hsprotect.net",
    "collector-pxzc5j78di.hsprotect.net",
    "hsprotect.net",
    "fpt.live.com",
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


def now_iso() -> str:
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


class JsonlWriter:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

    def write(self, obj: dict):
        with self.lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")


class TargetObserver(threading.Thread):
    def __init__(self, target: dict, writer: JsonlWriter, stop_at: float):
        super().__init__(daemon=True)
        self.target = target
        self.writer = writer
        self.stop_at = stop_at
        self.ws = None
        self.next_id = 0
        self.lock = threading.Lock()
        self.pending: dict[int, tuple[threading.Event, dict]] = {}
        self.responses: dict[str, dict] = {}

    def cmd(self, method: str, params: dict | None = None, timeout: float = 5.0) -> dict:
        with self.lock:
            self.next_id += 1
            mid = self.next_id
            ev = threading.Event()
            box = {}
            self.pending[mid] = (ev, box)
            self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        if not ev.wait(timeout):
            with self.lock:
                self.pending.pop(mid, None)
            raise TimeoutError(method)
        return box.get("msg", {})

    def run(self):
        title = self.target.get("title", "")
        url = self.target.get("url", "")
        print(f"[RawCDP] attach {self.target.get('id')} {title} {url}", flush=True)
        try:
            self.ws = websocket.create_connection(
                self.target["webSocketDebuggerUrl"],
                timeout=8,
                suppress_origin=True,
            )
            self.ws.settimeout(1.0)
            self.next_id += 1
            init_id = self.next_id
            self.ws.send(json.dumps({"id": init_id, "method": "Network.enable", "params": {}}))
            deadline = time.time() + 3
            enabled = False
            while time.time() < deadline:
                try:
                    msg = json.loads(self.ws.recv())
                except websocket.WebSocketTimeoutException:
                    continue
                if msg.get("id") == init_id:
                    enabled = True
                    break
            if not enabled:
                print(f"[RawCDP] Network.enable ack timeout {self.target.get('id')}; continuing", flush=True)
        except Exception as exc:
            print(f"[RawCDP] attach failed {self.target.get('id')}: {exc!r}", flush=True)
            try:
                if self.ws:
                    self.ws.close()
            except Exception:
                pass
            return

        while time.time() < self.stop_at:
            try:
                msg = json.loads(self.ws.recv())
            except websocket.WebSocketTimeoutException:
                continue
            except Exception as exc:
                print(f"[RawCDP] recv end {self.target.get('id')}: {exc!r}", flush=True)
                break

            mid = msg.get("id")
            if mid is not None:
                with self.lock:
                    item = self.pending.pop(mid, None)
                if item:
                    ev, box = item
                    box["msg"] = msg
                    ev.set()
                continue

            method = msg.get("method")
            params = msg.get("params") or {}
            try:
                if method == "Network.requestWillBeSent":
                    self.on_request(params)
                elif method == "Network.responseReceived":
                    self.on_response(params)
                elif method == "Network.loadingFinished":
                    self.on_loading_finished(params)
                elif method == "Network.loadingFailed":
                    self.on_loading_failed(params)
            except Exception as exc:
                print(f"[RawCDP] event error {method}: {exc!r}", flush=True)

        try:
            self.ws.close()
        except Exception:
            pass

    def on_request(self, params: dict):
        req = params.get("request") or {}
        url = req.get("url") or ""
        if not want(url):
            return
        rec = {
            "ts": now_iso(),
            "event": "request",
            "method": req.get("method"),
            "url": url,
            "resource_type": params.get("type", "").lower(),
            "headers": req.get("headers") or {},
        }
        if req.get("postData") is not None:
            rec["post_data"] = bounded(req.get("postData"))
        self.writer.write(rec)

    def on_response(self, params: dict):
        resp = params.get("response") or {}
        url = resp.get("url") or ""
        if not want(url):
            return
        req_id = params.get("requestId")
        rec = {
            "ts": now_iso(),
            "event": "response",
            "method": "",
            "url": url,
            "status": resp.get("status"),
            "headers": resp.get("headers") or {},
        }
        if req_id and want_body(url):
            self.responses[req_id] = rec
        else:
            self.writer.write(rec)

    def on_loading_finished(self, params: dict):
        req_id = params.get("requestId")
        rec = self.responses.pop(req_id, None)
        if not rec:
            return

        def fetch_body():
            try:
                msg = self.cmd("Network.getResponseBody", {"requestId": req_id}, timeout=8)
                result = msg.get("result") or {}
                body = result.get("body")
                if result.get("base64Encoded"):
                    rec["body_base64"] = bounded(body or "")
                else:
                    rec["body"] = bounded(body or "")
            except Exception as exc:
                rec["body_error"] = repr(exc)[:240]
            self.writer.write(rec)
            if "api/v1.0/risk/verify" in rec.get("url", ""):
                self.print_risk_verify(rec)
            if "signup.live.com/API/CreateAccount" in rec.get("url", "") and int(rec.get("status") or 0) == 200:
                print("[RawCDP] CreateAccount 200 captured", flush=True)

        threading.Thread(target=fetch_body, daemon=True).start()

    def on_loading_failed(self, params: dict):
        req_id = params.get("requestId")
        rec = self.responses.pop(req_id, None)
        if not rec:
            return
        rec["body_error"] = f"loadingFailed:{params.get('errorText')}"
        self.writer.write(rec)

    @staticmethod
    def print_risk_verify(rec: dict):
        body = str(rec.get("body") or "")
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
            f"[RawCDP] risk/verify status={rec.get('status')} "
            f"state={state or '-'} err={err_code or '-'} inner={inner_code or '-'}",
            flush=True,
        )


def list_targets(endpoint: str) -> list[dict]:
    with urllib.request.urlopen(endpoint.rstrip("/") + "/json/list", timeout=3) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Lightweight raw CDP network observer; no Playwright/Patchright attach.")
    ap.add_argument("--cdp-endpoint", default="http://127.0.0.1:19222")
    ap.add_argument("--timeout-seconds", type=int, default=600)
    ap.add_argument("--out", required=True)
    ap.add_argument("--poll-seconds", type=float, default=1.0)
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    writer = JsonlWriter(out)
    stop_at = time.time() + max(1, args.timeout_seconds)
    seen = set()
    observers: list[TargetObserver] = []
    print(f"[RawCDP] network log: {out.resolve()}", flush=True)

    while time.time() < stop_at:
        try:
            targets = list_targets(args.cdp_endpoint)
            for t in targets:
                if t.get("type") != "page":
                    continue
                tid = t.get("id")
                if tid in seen:
                    continue
                seen.add(tid)
                obs = TargetObserver(t, writer, stop_at)
                obs.start()
                observers.append(obs)
        except Exception as exc:
            print(f"[RawCDP] poll error: {exc!r}", flush=True)
        time.sleep(max(0.2, args.poll_seconds))

    print("[RawCDP] done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
