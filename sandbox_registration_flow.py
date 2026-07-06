#!/usr/bin/env python
"""Run a controlled sandbox registration flow and save proof artifacts."""

from __future__ import annotations

import argparse
import json
import secrets
import string
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = ROOT / "Results" / "sandbox_registration"


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CTF Sandbox Registration</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7fb;
      --panel: #ffffff;
      --ink: #17202a;
      --muted: #5d6d7e;
      --line: #ccd4df;
      --blue: #1454d8;
      --green: #1f7a4d;
      --red: #b42318;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: var(--bg);
      color: var(--ink);
      font-family: Segoe UI, system-ui, -apple-system, sans-serif;
    }
    main {
      width: min(480px, calc(100vw - 32px));
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 24px;
      box-shadow: 0 12px 30px rgba(20, 35, 60, 0.08);
    }
    h1 {
      margin: 0 0 18px;
      font-size: 24px;
      line-height: 1.2;
      letter-spacing: 0;
    }
    label {
      display: block;
      margin: 14px 0 6px;
      color: var(--muted);
      font-size: 13px;
    }
    input {
      width: 100%;
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 11px;
      color: var(--ink);
      font: inherit;
    }
    .hold-row {
      display: flex;
      align-items: center;
      gap: 12px;
      margin: 18px 0 16px;
    }
    #holdButton {
      width: 180px;
      min-height: 48px;
      border: 2px solid #2f3742;
      border-radius: 999px;
      background: #fff;
      color: #2f3742;
      font-weight: 700;
      font-size: 15px;
      letter-spacing: 0;
      cursor: pointer;
      user-select: none;
    }
    #holdButton.pressed {
      background: #eef4ff;
      border-color: var(--blue);
      color: var(--blue);
    }
    #holdButton.done {
      background: #edf8f2;
      border-color: var(--green);
      color: var(--green);
    }
    #holdState {
      min-width: 130px;
      color: var(--muted);
      font-size: 13px;
    }
    #submitButton {
      width: 100%;
      min-height: 44px;
      border: 0;
      border-radius: 6px;
      background: var(--blue);
      color: #fff;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }
    #status {
      min-height: 22px;
      margin-top: 16px;
      font-size: 14px;
      color: var(--muted);
    }
    #status.success { color: var(--green); }
    #status.error { color: var(--red); }
  </style>
</head>
<body>
  <main>
    <h1>CTF Sandbox Registration</h1>
    <form id="registrationForm">
      <label for="email">Email</label>
      <input id="email" name="email" autocomplete="off" required>

      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="new-password" required>

      <div class="hold-row">
        <button id="holdButton" type="button" aria-label="Press and hold">PRESS &amp; HOLD</button>
        <span id="holdState">Waiting</span>
      </div>

      <button id="submitButton" type="submit">Create account</button>
      <div id="status" role="status"></div>
    </form>
  </main>
  <script>
    const holdButton = document.querySelector("#holdButton");
    const holdState = document.querySelector("#holdState");
    const statusBox = document.querySelector("#status");
    let holdStarted = 0;
    let holdTimer = 0;
    let challengeToken = "";

    function setStatus(text, type) {
      statusBox.textContent = text;
      statusBox.className = type || "";
    }

    holdButton.addEventListener("pointerdown", () => {
      holdStarted = Date.now();
      challengeToken = "";
      holdButton.className = "pressed";
      holdState.textContent = "Holding";
      clearTimeout(holdTimer);
      holdTimer = setTimeout(() => {
        challengeToken = "sandbox-" + holdStarted;
        holdButton.className = "done";
        holdState.textContent = "Verified";
      }, 1200);
    });

    for (const eventName of ["pointerup", "pointercancel", "pointerleave"]) {
      holdButton.addEventListener(eventName, () => {
        if (!challengeToken) {
          clearTimeout(holdTimer);
          holdButton.className = "";
          holdState.textContent = "Hold longer";
        }
      });
    }

    document.querySelector("#registrationForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!challengeToken) {
        setStatus("Complete the hold challenge first.", "error");
        return;
      }
      const payload = {
        email: document.querySelector("#email").value,
        password: document.querySelector("#password").value,
        challengeToken
      };
      const response = await fetch("/api/register", {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      if (!response.ok) {
        setStatus(data.error || "Registration failed.", "error");
        return;
      }
      setStatus("ACCOUNT_CREATED " + data.email, "success");
      window.__sandboxAccount = data;
    });
  </script>
</body>
</html>
"""


class SandboxState:
    def __init__(self) -> None:
        self.accounts: list[dict[str, str]] = []


class SandboxHandler(BaseHTTPRequestHandler):
    state: SandboxState

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/api/register":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length") or "0")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError:
            self._json({"error": "Invalid JSON"}, status=400)
            return
        email = str(payload.get("email") or "").strip().lower()
        password = str(payload.get("password") or "")
        challenge_token = str(payload.get("challengeToken") or "")
        if not email.endswith("@sandbox.invalid") or len(email) < 18:
            self._json({"error": "Email must use @sandbox.invalid"}, status=400)
            return
        if len(password) < 12:
            self._json({"error": "Password is too short"}, status=400)
            return
        if not challenge_token.startswith("sandbox-"):
            self._json({"error": "Hold challenge not completed"}, status=400)
            return
        account = {
            "email": email,
            "password": password,
            "id": "acct_" + secrets.token_hex(6),
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "environment": "ctf-sandbox-local",
        }
        self.state.accounts.append(account)
        self._json(account)

    def log_message(self, fmt: str, *args: object) -> None:
        print("[sandbox-server] " + fmt % args)

    def _json(self, payload: dict[str, str], status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def new_password(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits
    return "Ctf!" + "".join(secrets.choice(alphabet) for _ in range(length - 4))


def start_server() -> tuple[ThreadingHTTPServer, str]:
    state = SandboxState()

    class BoundHandler(SandboxHandler):
        pass

    BoundHandler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), BoundHandler)
    thread = threading.Thread(target=server.serve_forever, name="sandbox-registration-server", daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}/"


def run_flow(base_url: str, out_dir: Path, headed: bool = False) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    account = {
        "email": f"ctf-{secrets.token_hex(5)}@sandbox.invalid",
        "password": new_password(),
    }
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headed)
        page = browser.new_page(viewport={"width": 1280, "height": 720})
        try:
            page.goto(base_url, wait_until="domcontentloaded", timeout=20_000)
            page.fill("#email", account["email"])
            page.fill("#password", account["password"])
            hold = page.locator("#holdButton")
            box = hold.bounding_box(timeout=5_000)
            if not box:
                raise RuntimeError("hold button has no bounding box")
            x = box["x"] + box["width"] / 2
            y = box["y"] + box["height"] / 2
            page.mouse.move(x, y)
            page.mouse.down()
            page.wait_for_timeout(1400)
            page.mouse.up()
            page.click("#submitButton")
            page.wait_for_selector("#status.success", timeout=10_000)
            created = page.evaluate("window.__sandboxAccount")
            if not created or created.get("email") != account["email"]:
                raise RuntimeError(f"unexpected account response: {created!r}")
            account.update(created)
            page.screenshot(path=str(out_dir / "success.png"), full_page=True)
            (out_dir / "account.json").write_text(json.dumps(account, indent=2), encoding="utf-8")
            return account
        except Exception as exc:
            page.screenshot(path=str(out_dir / "failure.png"), full_page=True)
            (out_dir / "failure.json").write_text(
                json.dumps({"error": repr(exc), "email": account["email"]}, indent=2),
                encoding="utf-8",
            )
            raise
        finally:
            browser.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the controlled sandbox registration flow.")
    parser.add_argument("--headed", action="store_true", help="Run Chromium headed.")
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()

    stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    out_dir = args.out_dir or RESULTS_ROOT / stamp
    server, base_url = start_server()
    print(f"SANDBOX_REGISTRATION_URL={base_url}")
    try:
        account = run_flow(base_url, out_dir, headed=args.headed)
        print("SANDBOX_REGISTRATION_SUCCESS=1")
        print(f"SANDBOX_ACCOUNT_EMAIL={account['email']}")
        print(f"SANDBOX_ACCOUNT_PASSWORD={account['password']}")
        print(f"SANDBOX_ARTIFACT_DIR={out_dir}")
        return 0
    finally:
        server.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
