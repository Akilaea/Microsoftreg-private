import os
import time
import json
import hashlib
import random
import threading
from datetime import datetime
from abc import ABC, abstractmethod
from settings import load_config

try:
    from faker import Faker
except ImportError:
    Faker = None

class BaseBrowserController(ABC):
    """
    所有浏览器通用的接口和共享逻辑
    """

    def __init__(self):
        data = load_config()
        self.wait_time = data['bot_protection_wait'] * 1000
        self.max_captcha_retries = data['max_captcha_retries']
        self.enable_oauth2 = data["oauth2"]['enable_oauth2']
        self.proxy = data['proxy']
        self.email_suffix = data['email_suffix']
        self.context_options = data.get("context", {})
        self.manual_captcha = data.get("manual_captcha", False)
        self.manual_captcha_wait_seconds = data.get("manual_captcha_wait_seconds", 180)
        self.manual_post_verify_wait_seconds = data.get("manual_post_verify_wait_seconds", 10)
        self.post_captcha_account_wait_seconds = data.get("post_captcha_account_wait_seconds", 0)
        self.signup_country_label = data.get("signup_country_label") or os.environ.get("OUTLOOK_SIGNUP_COUNTRY_LABEL", "")
        self.signup_entry_url = data.get("signup_entry_url") or os.environ.get("OUTLOOK_SIGNUP_ENTRY_URL", "")
        self.signup_fill_mode = str(
            data.get("signup_fill_mode") or os.environ.get("OUTLOOK_SIGNUP_FILL_MODE", "ui")
        ).strip().lower()
        self.signup_fill_profile = data.get("signup_fill_profile", {}) or {}
        self.signup_check_available_prefetch_mode = str(
            data.get("signup_check_available_prefetch_mode")
            or os.environ.get("OUTLOOK_SIGNUP_CHECK_AVAILABLE_PREFETCH_MODE", "sync")
        ).strip().lower()
        self.signup_submit_mode = str(
            data.get("signup_submit_mode")
            or os.environ.get("OUTLOOK_SIGNUP_SUBMIT_MODE", "dom_fast")
        ).strip().lower()
        self.signup_name_submit_mode = str(
            data.get("signup_name_submit_mode")
            or os.environ.get("OUTLOOK_SIGNUP_NAME_SUBMIT_MODE", "native")
        ).strip().lower()
        try:
            self.signup_protocol_takeover_cookie_timeout_ms = int(
                data.get("signup_protocol_takeover_cookie_timeout_ms")
                or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_COOKIE_TIMEOUT_MS", "9000")
            )
        except Exception:
            self.signup_protocol_takeover_cookie_timeout_ms = 9000
        try:
            self.signup_protocol_takeover_post_success_settle_ms = int(
                data.get("signup_protocol_takeover_post_success_settle_ms")
                or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_POST_SUCCESS_SETTLE_MS", "650")
            )
        except Exception:
            self.signup_protocol_takeover_post_success_settle_ms = 650
        self.signup_protocol_takeover_preverify_transport = str(
            data.get("signup_protocol_takeover_preverify_transport")
            or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_PREVERIFY_TRANSPORT", "page_fetch")
            or "page_fetch"
        ).strip().lower()
        try:
            self.signup_protocol_takeover_thin_bootstrap_wait_ms = int(
                data.get("signup_protocol_takeover_thin_bootstrap_wait_ms")
                or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_THIN_BOOTSTRAP_WAIT_MS", "12000")
            )
        except Exception:
            self.signup_protocol_takeover_thin_bootstrap_wait_ms = 12000
        self.signup_protocol_takeover_thin_goto_wait_until = str(
            data.get("signup_protocol_takeover_thin_goto_wait_until")
            or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_THIN_GOTO_WAIT_UNTIL", "commit")
            or "commit"
        ).strip().lower()
        try:
            self.signup_protocol_takeover_preverify_min_total_ms = int(
                data.get("signup_protocol_takeover_preverify_min_total_ms")
                or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_PREVERIFY_MIN_TOTAL_MS", "0")
            )
        except Exception:
            self.signup_protocol_takeover_preverify_min_total_ms = 0
        self.signup_protocol_takeover_pxvid_fallback = str(
            data.get("signup_protocol_takeover_pxvid_fallback")
            or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_PXVID_FALLBACK", "")
        ).strip().lower() in {"1", "true", "yes", "on"}
        self.signup_protocol_takeover_use_observed_risk_init = str(
            data.get("signup_protocol_takeover_use_observed_risk_init")
            or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_USE_OBSERVED_RISK_INIT", "1")
        ).strip().lower() not in {"0", "false", "no", "off"}
        try:
            self.signup_protocol_takeover_observed_risk_init_wait_ms = int(
                data.get("signup_protocol_takeover_observed_risk_init_wait_ms")
                or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_OBSERVED_RISK_INIT_WAIT_MS", "2500")
            )
        except Exception:
            self.signup_protocol_takeover_observed_risk_init_wait_ms = 2500
        self.signup_protocol_takeover_risk_init_transport = str(
            data.get("signup_protocol_takeover_risk_init_transport")
            or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_RISK_INIT_TRANSPORT", "auto")
            or "auto"
        ).strip().lower()
        self.signup_protocol_takeover_solution_fallbacks = str(
            data.get("signup_protocol_takeover_solution_fallbacks")
            or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_SOLUTION_FALLBACKS", "1")
        ).strip().lower() not in {"0", "false", "no", "off"}
        try:
            self.signup_protocol_takeover_solution_candidate_limit = int(
                data.get("signup_protocol_takeover_solution_candidate_limit")
                or os.environ.get("OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_SOLUTION_CANDIDATE_LIMIT", "5")
            )
        except Exception:
            self.signup_protocol_takeover_solution_candidate_limit = 5
        try:
            self.signup_submit_fast_wait_ms = int(
                data.get("signup_submit_fast_wait_ms")
                or os.environ.get("OUTLOOK_SIGNUP_SUBMIT_FAST_WAIT_MS", "1800")
            )
        except Exception:
            self.signup_submit_fast_wait_ms = 1800
        def _fast_wait_ms(config_key, env_key, default_value):
            try:
                value = data.get(config_key)
                if value is None or value == "":
                    value = os.environ.get(env_key, default_value)
                return max(0, int(value))
            except Exception:
                return int(default_value)
        # Fast-fill pacing knobs.  Defaults preserve the previously validated
        # 5s-stable behavior; batch/single-run scripts can lower them for
        # controlled semiprotocol fill-speed experiments without touching the
        # proof path.
        self.signup_fast_post_email_wait_ms = _fast_wait_ms(
            "signup_fast_post_email_wait_ms",
            "OUTLOOK_SIGNUP_FAST_POST_EMAIL_WAIT_MS",
            250,
        )
        self.signup_fast_pre_password_submit_wait_ms = _fast_wait_ms(
            "signup_fast_pre_password_submit_wait_ms",
            "OUTLOOK_SIGNUP_FAST_PRE_PASSWORD_SUBMIT_WAIT_MS",
            220,
        )
        self.signup_fast_post_password_wait_ms = _fast_wait_ms(
            "signup_fast_post_password_wait_ms",
            "OUTLOOK_SIGNUP_FAST_POST_PASSWORD_WAIT_MS",
            300,
        )
        self.signup_fast_birth_input_settle_ms = _fast_wait_ms(
            "signup_fast_birth_input_settle_ms",
            "OUTLOOK_SIGNUP_FAST_BIRTH_INPUT_SETTLE_MS",
            180,
        )
        self.signup_fast_birth_select_settle_ms = _fast_wait_ms(
            "signup_fast_birth_select_settle_ms",
            "OUTLOOK_SIGNUP_FAST_BIRTH_SELECT_SETTLE_MS",
            120,
        )
        self.signup_fast_dob_ready_wait_ms = _fast_wait_ms(
            "signup_fast_dob_ready_wait_ms",
            "OUTLOOK_SIGNUP_FAST_DOB_READY_WAIT_MS",
            0,
        )
        self.signup_fast_name_ready_wait_ms = _fast_wait_ms(
            "signup_fast_name_ready_wait_ms",
            "OUTLOOK_SIGNUP_FAST_NAME_READY_WAIT_MS",
            120,
        )
        self.signup_fast_name_submit_wait_ms = _fast_wait_ms(
            "signup_fast_name_submit_wait_ms",
            "OUTLOOK_SIGNUP_FAST_NAME_SUBMIT_WAIT_MS",
            9000,
        )
        self.signup_fast_name_submit_poll_ms = _fast_wait_ms(
            "signup_fast_name_submit_poll_ms",
            "OUTLOOK_SIGNUP_FAST_NAME_SUBMIT_POLL_MS",
            350,
        )
        self.signup_fast_left_name_page_ms = _fast_wait_ms(
            "signup_fast_left_name_page_ms",
            "OUTLOOK_SIGNUP_FAST_LEFT_NAME_PAGE_MS",
            10000,
        )
        self.signup_fast_post_name_submit_buffer_ms = _fast_wait_ms(
            "signup_fast_post_name_submit_buffer_ms",
            "OUTLOOK_SIGNUP_FAST_POST_NAME_SUBMIT_BUFFER_MS",
            400,
        )
        self.no_js_input_fallback = bool(data.get("no_js_input_fallback", False))
        self.capture_network = data.get("capture_network", False)
        self.capture_network_post_data = data.get("capture_network_post_data", False)
        self.capture_network_headers = data.get("capture_network_headers", False)
        self.capture_network_response_body = data.get("capture_network_response_body", False)
        self.capture_network_response_body_keywords = data.get("capture_network_response_body_keywords", [])
        self.capture_network_max_body = data.get("capture_network_max_body", 200000)
        self.redact_network_cookies = data.get("redact_network_cookies", True)
        self.capture_challenge = data.get("capture_challenge", False)
        self.challenge_dump_max_html = data.get("challenge_dump_max_html", 300000)
        self.captcha_options = data.get("captcha", {})
        self.learn_captcha_events = data.get("learn_captcha_events", False)
        self.network_url_keywords = data.get("network_url_keywords", [
            "signup.live.com",
            "login.live.com",
            "account.live.com",
            "outlook.live.com",
            "hsprotect.net",
            "browser.events.data.microsoft.com"
        ])

        self.thread_local = threading.local()
        self.cleanup_lock = threading.Lock()
        self.active_resources = []  # 记录资源以便关闭
        self.signup_network_lock = threading.Lock()
        self.signup_network_state = {}

        self.results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Results')
        os.makedirs(self.results_dir, exist_ok=True)
        self.diagnostics_dir = os.path.join(self.results_dir, "diagnostics")
        os.makedirs(self.diagnostics_dir, exist_ok=True)
        self.network_dir = os.path.join(self.results_dir, "network")
        os.makedirs(self.network_dir, exist_ok=True)
        self.challenge_dir = os.path.join(self.results_dir, "challenge")
        os.makedirs(self.challenge_dir, exist_ok=True)
        self.captcha_events_dir = os.path.join(self.results_dir, "captcha_events")
        os.makedirs(self.captcha_events_dir, exist_ok=True)


    @abstractmethod
    def launch_browser(self):
        """
        获取浏览器实例,返回playwright_instance, browser_instance
        """
        pass

    @abstractmethod
    def handle_captcha(self, page):
        """
        验证码处理流程
        """
        pass

    @abstractmethod 
    def clean_up(self, page=None, type = "all_browser"):
        """
        清理自己创建的内容
        一个是单进程结束后关闭进程，另一个是程序结束后清除所有内容
        """
        pass

    @abstractmethod
    def get_thread_page(self):
        """
        返回页面
        """


    def get_thread_browser(self):
        """
        通用逻辑:获取不同进程的浏览器
        """

        if not hasattr(self.thread_local,"browser"):

            p, b  = self.launch_browser()
            if not p:
                return False

            self.thread_local.playwright = p
            self.thread_local.browser = b

            with self.cleanup_lock:
                self.active_resources.append((p, b))

        return self.thread_local.browser

    def save_diagnostic(self, page, tag, email=None):
        """
        保存失败点现场，方便区分：
        - 自动化/指纹被识别
        - IP/频率风控
        - 选择器过期
        - 验证码类型变化
        """
        if not page:
            return

        safe_email = (email or "unknown").replace("@", "_").replace(":", "_")
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(self.diagnostics_dir, f"{stamp}_{tag}_{safe_email}")

        try:
            page.screenshot(path=f"{base}.png", full_page=True)
        except Exception:
            pass

        lines = []
        try:
            lines.append(f"url={page.url}")
        except Exception:
            pass
        try:
            lines.append(f"title={page.title()}")
        except Exception:
            pass
        try:
            text = page.locator("body").inner_text(timeout=2000)
            lines.append("body_text_begin")
            lines.append(text[:5000])
            lines.append("body_text_end")
        except Exception:
            pass

        if lines:
            try:
                with open(f"{base}.txt", "w", encoding="utf-8") as f:
                    f.write("\n".join(lines))
            except Exception:
                pass

    def _safe_email_for_filename(self, email=None):
        return (email or "unknown").replace("@", "_").replace(":", "_").replace("\\", "_").replace("/", "_")

    def _network_interesting(self, url):
        return any(keyword in url for keyword in self.network_url_keywords)

    def _filtered_headers(self, headers):
        if not self.capture_network_headers or not headers:
            return None
        result = {}
        for key, value in dict(headers).items():
            lk = key.lower()
            if self.redact_network_cookies and lk in {"cookie", "authorization", "x-ms-refreshtokencredential"}:
                result[key] = "<redacted>"
            else:
                result[key] = value
        return result

    def _bounded_text(self, text):
        if text is None:
            return None
        if len(text) <= self.capture_network_max_body:
            return text
        return text[:self.capture_network_max_body] + f"\n<truncated {len(text) - self.capture_network_max_body} chars>"

    def attach_network_logger(self, page, email=None):
        """
        记录注册流程的请求顺序，为协议复现提供证据。

        默认只记录关键域名；POST body/headers/response body 由配置开关控制。
        日志仅落盘到 Results/network，不在控制台打印敏感内容。
        """
        if not self.capture_network or not page:
            return None

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_email = self._safe_email_for_filename(email)
        log_path = os.path.join(self.network_dir, f"{stamp}_{safe_email}.jsonl")
        lock = threading.Lock()
        page_key = id(page)
        with self.signup_network_lock:
            self.signup_network_state[page_key] = {
                "create_requests": 0,
                "create_responses": [],
                "create_success": False,
                "create_done": False,
                "create_failures": [],
                "create_last": {},
                "risk_verify_responses": [],
                "riskblock": False,
            }

        def classify_create_account_response(status=None, body=None):
            summary = {
                "ok": False,
                "terminal": False,
                "status": int(status or 0),
                "reason": "",
                "error_code": "",
                "keys": [],
                "signinName": "",
            }
            try:
                if int(status or 0) != 200:
                    summary.update({"terminal": True, "reason": f"http_{int(status or 0)}"})
                    return summary
            except Exception:
                summary.update({"terminal": True, "reason": f"http_{status}"})
                return summary
            text = str(body or "").strip()
            if not text:
                summary.update({"terminal": True, "reason": "empty_body"})
                return summary
            try:
                parsed = json.loads(text)
            except Exception:
                summary.update({"terminal": True, "reason": "json_parse_failed"})
                return summary
            if not isinstance(parsed, dict):
                summary.update({"terminal": True, "reason": type(parsed).__name__})
                return summary
            summary["keys"] = sorted([str(k) for k in parsed.keys()])
            err = parsed.get("error")
            if isinstance(err, dict):
                summary.update({
                    "terminal": True,
                    "reason": "error",
                    "error_code": str(err.get("code") or ""),
                })
                return summary
            # Real successful CreateAccount responses contain mailbox/session
            # material, not just HTTP 200.  The important markers observed in
            # clean samples are signinName + slt plus redirectUrl/encPuid.
            success_markers = [
                bool(parsed.get("signinName")),
                bool(parsed.get("slt")),
                bool(parsed.get("redirectUrl")),
                bool(parsed.get("encPuid")),
            ]
            if sum(1 for x in success_markers if x) >= 2 and parsed.get("signinName") and parsed.get("slt"):
                summary.update({
                    "ok": True,
                    "terminal": True,
                    "reason": "success_body",
                    "signinName": str(parsed.get("signinName") or ""),
                })
                return summary
            summary.update({"terminal": True, "reason": "unknown_body_shape"})
            return summary

        def note_create_account(kind, status=None, body=None):
            try:
                with self.signup_network_lock:
                    state = self.signup_network_state.setdefault(page_key, {
                        "create_requests": 0,
                        "create_responses": [],
                        "create_success": False,
                        "create_done": False,
                        "create_failures": [],
                        "create_last": {},
                        "risk_verify_responses": [],
                        "riskblock": False,
                    })
                    if kind == "request":
                        state["create_requests"] = int(state.get("create_requests") or 0) + 1
                    elif kind == "response":
                        state.setdefault("create_responses", []).append(status)
                        summary = classify_create_account_response(status, body)
                        state["create_last"] = summary
                        if summary.get("ok"):
                            state["create_success"] = True
                            state["create_done"] = True
                        elif summary.get("terminal"):
                            state["create_done"] = True
                            state.setdefault("create_failures", []).append(summary)
            except Exception:
                pass

        def note_risk_verify(status=None):
            try:
                with self.signup_network_lock:
                    state = self.signup_network_state.setdefault(page_key, {
                        "create_requests": 0,
                        "create_responses": [],
                        "create_success": False,
                        "risk_verify_responses": [],
                        "riskblock": False,
                    })
                    state.setdefault("risk_verify_responses", []).append(status)
                    if int(status or 0) in {401, 403, 429}:
                        state["riskblock"] = True
            except Exception:
                pass

        def write_event(record):
            with lock:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")

        def get_post_data(request):
            try:
                data = request.post_data
            except Exception:
                try:
                    data = request.post_data()
                except Exception:
                    data = None
            if not data:
                return None

            if self.capture_network_post_data:
                return {
                    "post_data": self._bounded_text(data),
                    "post_data_len": len(data),
                    "post_data_sha256": hashlib.sha256(data.encode("utf-8", errors="ignore")).hexdigest()
                }
            return {
                "post_data": "<redacted>",
                "post_data_len": len(data),
                "post_data_sha256": hashlib.sha256(data.encode("utf-8", errors="ignore")).hexdigest()
            }

        def on_request(request):
            try:
                url = request.url
                if not self._network_interesting(url):
                    return
                if request.method == "POST" and "signup.live.com/API/CreateAccount" in url:
                    note_create_account("request")
                record = {
                    "ts": datetime.now().isoformat(),
                    "event": "request",
                    "method": request.method,
                    "url": url,
                    "resource_type": getattr(request, "resource_type", None),
                }
                headers = self._filtered_headers(getattr(request, "headers", None))
                if headers is not None:
                    record["headers"] = headers
                post_data = get_post_data(request)
                if post_data is not None:
                    record.update(post_data)
                write_event(record)
            except Exception as exc:
                write_event({
                    "ts": datetime.now().isoformat(),
                    "event": "logger_error",
                    "where": "request",
                    "error": repr(exc)
                })

        def on_response(response):
            try:
                request = response.request
                url = response.url
                if not self._network_interesting(url):
                    return
                if request.method == "POST" and "/api/v1.0/risk/verify" in url:
                    note_risk_verify(response.status)
                record = {
                    "ts": datetime.now().isoformat(),
                    "event": "response",
                    "method": request.method,
                    "url": url,
                    "status": response.status,
                }
                headers = self._filtered_headers(getattr(response, "headers", None))
                if headers is not None:
                    record["headers"] = headers
                body = None
                should_capture_body = self.capture_network_response_body
                if should_capture_body and self.capture_network_response_body_keywords:
                    should_capture_body = any(keyword in url for keyword in self.capture_network_response_body_keywords)
                if should_capture_body:
                    try:
                        body = response.text()
                        record["body"] = self._bounded_text(body)
                        record["body_len"] = len(body)
                        record["body_sha256"] = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()
                    except Exception as exc:
                        record["body_error"] = repr(exc)
                if request.method == "POST" and "signup.live.com/API/CreateAccount" in url:
                    # Classify by response body, not HTTP 200 alone: CreateAccount
                    # can return 200 with {"error":{"code":"1350",...}}, which
                    # means the account was not created.
                    if body is None:
                        try:
                            body = response.text()
                        except Exception:
                            body = ""
                    note_create_account("response", response.status, body)
                write_event(record)
            except Exception as exc:
                write_event({
                    "ts": datetime.now().isoformat(),
                    "event": "logger_error",
                    "where": "response",
                    "error": repr(exc)
                })

        page.on("request", on_request)
        page.on("response", on_response)
        print(f"[Trace] - network log: {log_path}")
        return log_path

    def get_create_account_state(self, page):
        try:
            with self.signup_network_lock:
                return dict(self.signup_network_state.get(id(page), {}))
        except Exception:
            return {}

    def wait_for_create_account_success(self, page, timeout_ms=25000):
        """
        防止把“验证码 iframe 消失/未出现”误判成注册完成。
        真正完成需要看到 signup.live.com/API/CreateAccount 的成功响应体。
        注意：该接口会出现 HTTP 200 + {"error":{"code":"1350"}}，这不是成功。
        """
        if not self.capture_network:
            return True, {"reason": "network_capture_disabled"}
        deadline = time.time() + max(1000, int(timeout_ms or 0)) / 1000
        last = {}
        while time.time() < deadline:
            last = self.get_create_account_state(page)
            if last.get("create_success"):
                return True, last
            if last.get("create_done") and last.get("create_failures"):
                return False, last
            page.wait_for_timeout(350)
        return False, last

    def save_challenge_snapshot(self, page, email=None, tag="challenge"):
        """
        保存验证码阶段现场：
        - 整页截图
        - iframe 列表及坐标
        - page/frame HTML
        - frame URL/name 等元数据
        """
        if not page:
            return None

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_email = self._safe_email_for_filename(email)
        base_dir = os.path.join(self.challenge_dir, f"{stamp}_{tag}_{safe_email}")
        os.makedirs(base_dir, exist_ok=True)

        meta = {
            "ts": datetime.now().isoformat(),
            "tag": tag,
            "email": email,
            "page_url": None,
            "page_title": None,
            "iframes": [],
            "frames": [],
        }

        try:
            meta["page_url"] = page.url
        except Exception:
            pass
        try:
            meta["page_title"] = page.title()
        except Exception:
            pass

        try:
            page.screenshot(path=os.path.join(base_dir, "page.png"), full_page=True)
        except Exception as exc:
            meta["page_screenshot_error"] = repr(exc)

        try:
            page_html = page.content()
            if len(page_html) > self.challenge_dump_max_html:
                page_html = page_html[:self.challenge_dump_max_html] + "\n<!-- truncated -->"
            with open(os.path.join(base_dir, "page.html"), "w", encoding="utf-8") as f:
                f.write(page_html)
        except Exception as exc:
            meta["page_html_error"] = repr(exc)

        try:
            iframe_infos = page.locator("iframe").evaluate_all(
                """els => els.map((el, idx) => {
                    const r = el.getBoundingClientRect();
                    return {
                        idx,
                        src: el.src || el.getAttribute('src'),
                        title: el.title || el.getAttribute('title'),
                        id: el.id || null,
                        name: el.name || el.getAttribute('name'),
                        ariaLabel: el.getAttribute('aria-label'),
                        className: el.className || null,
                        style: el.getAttribute('style'),
                        rect: {x: r.x, y: r.y, width: r.width, height: r.height}
                    };
                })"""
            )
            meta["iframes"] = iframe_infos
        except Exception as exc:
            meta["iframe_list_error"] = repr(exc)

        try:
            iframe_count = page.locator("iframe").count()
            for idx in range(min(iframe_count, 12)):
                try:
                    page.locator("iframe").nth(idx).screenshot(path=os.path.join(base_dir, f"iframe_{idx}.png"))
                except Exception as exc:
                    meta.setdefault("iframe_screenshot_errors", []).append({"idx": idx, "error": repr(exc)})
        except Exception:
            pass

        try:
            for idx, frame in enumerate(page.frames):
                frame_meta = {
                    "idx": idx,
                    "name": None,
                    "url": None,
                    "html_file": None,
                    "html_error": None,
                }
                try:
                    frame_meta["name"] = frame.name
                except Exception:
                    pass
                try:
                    frame_meta["url"] = frame.url
                except Exception:
                    pass
                try:
                    html = frame.content()
                    if len(html) > self.challenge_dump_max_html:
                        html = html[:self.challenge_dump_max_html] + "\n<!-- truncated -->"
                    frame_file = f"frame_{idx}.html"
                    with open(os.path.join(base_dir, frame_file), "w", encoding="utf-8") as f:
                        f.write(html)
                    frame_meta["html_file"] = frame_file
                except Exception as exc:
                    frame_meta["html_error"] = repr(exc)
                meta["frames"].append(frame_meta)
        except Exception as exc:
            meta["frames_error"] = repr(exc)

        with open(os.path.join(base_dir, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

        print(f"[Challenge] - snapshot saved: {base_dir}")
        return base_dir

    def attach_captcha_event_logger(self, page, email=None):
        """
        手动学习模式：在所有 frame 中安装 pointer/mouse/touch 事件记录器。
        用户手动长按后，事件会经 console 回传并落盘，用来拟合自动化长按参数。
        """
        if not self.learn_captcha_events or not page:
            return None

        events = []
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_email = self._safe_email_for_filename(email)
        log_path = os.path.join(self.captcha_events_dir, f"{stamp}_{safe_email}.jsonl")
        prefix = "__CAPTCHA_EVENT__"
        lock = threading.Lock()

        def get_msg_text(msg):
            try:
                text = msg.text
                if callable(text):
                    text = text()
                return text
            except Exception:
                try:
                    return msg.text()
                except Exception:
                    return ""

        def on_console(msg):
            text = get_msg_text(msg)
            if not text or not text.startswith(prefix):
                return
            payload = text[len(prefix):]
            try:
                record = json.loads(payload)
            except Exception:
                record = {"raw": payload}
            record["recv_ts"] = datetime.now().isoformat()
            with lock:
                events.append(record)
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")

        page.on("console", on_console)

        recorder_script = r"""
        (() => {
          if (window.__captchaRecorderInstalled) return "already";
          window.__captchaRecorderInstalled = true;
          const emit = (e) => {
            try {
              const t = e.target;
              const r = t && t.getBoundingClientRect ? t.getBoundingClientRect() : null;
              const doc = document;
              const payload = {
                type: e.type,
                now: Date.now(),
                perfNow: (typeof performance !== "undefined" ? performance.now() : null),
                url: location.href,
                clientX: e.clientX ?? null,
                clientY: e.clientY ?? null,
                screenX: e.screenX ?? null,
                screenY: e.screenY ?? null,
                pageX: e.pageX ?? null,
                pageY: e.pageY ?? null,
                button: e.button ?? null,
                buttons: e.buttons ?? null,
                pointerType: e.pointerType ?? null,
                isTrusted: e.isTrusted,
                target: t ? {
                  tag: t.tagName,
                  id: t.id || null,
                  role: t.getAttribute ? t.getAttribute("role") : null,
                  aria: t.getAttribute ? t.getAttribute("aria-label") : null,
                  text: (t.innerText || t.textContent || "").slice(0, 120),
                  rect: r ? {x: r.x, y: r.y, width: r.width, height: r.height} : null
                } : null,
                viewport: {width: innerWidth, height: innerHeight},
                active: doc.activeElement ? {
                  tag: doc.activeElement.tagName,
                  id: doc.activeElement.id || null,
                  role: doc.activeElement.getAttribute ? doc.activeElement.getAttribute("role") : null
                } : null
              };
              console.log("__CAPTCHA_EVENT__" + JSON.stringify(payload));
            } catch (err) {
              console.log("__CAPTCHA_EVENT__" + JSON.stringify({type:"recorder_error", error:String(err)}));
            }
          };
          ["pointerdown","pointermove","pointerup","pointercancel","mousedown","mousemove","mouseup","touchstart","touchmove","touchend","keydown","keyup"].forEach(
            type => document.addEventListener(type, emit, true)
          );
          return "installed";
        })();
        """

        installed = 0
        for frame in page.frames:
            try:
                frame.evaluate(recorder_script)
                installed += 1
            except Exception:
                pass

        print(f"[Learn] - captcha event logger installed in {installed} frames: {log_path}")

        def finalize():
            summary_path = log_path + ".summary.json"
            summary = {
                "event_count": len(events),
                "log_path": log_path,
                "created_at": stamp,
                "email": email,
            }
            try:
                down_events = [e for e in events if e.get("type") in ("pointerdown", "mousedown", "touchstart")]
                up_events = [e for e in events if e.get("type") in ("pointerup", "mouseup", "touchend", "pointercancel")]
                if down_events and up_events:
                    first_down = down_events[0]
                    last_up = up_events[-1]
                    if first_down.get("perfNow") is not None and last_up.get("perfNow") is not None:
                        summary["hold_ms"] = last_up["perfNow"] - first_down["perfNow"]
                    summary["first_down"] = first_down
                    summary["last_up"] = last_up
            except Exception as exc:
                summary["summary_error"] = repr(exc)

            with open(summary_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, ensure_ascii=False, indent=2)
            print(f"[Learn] - captcha event summary: {summary_path}")
            return summary_path

        return finalize

    def outlook_register(self, page, email, password):
        """
        通用逻辑:注册邮箱
        """

        fill_profile = getattr(self, "signup_fill_profile", {}) or {}
        signup_mode = str(getattr(self, "signup_fill_mode", "ui") or "ui").strip().lower()
        protocol_takeover_modes = {
            "protocol_takeover",
            "protocol_takeover_v1",
            "takeover_v1",
            "protocol_v1",
            "protocol_takeover_thin",
            "thin_protocol_takeover",
            "protocol_takeover_v2",
            "takeover_v2",
        }
        protocol_takeover_thin = signup_mode in {
            "protocol_takeover_thin",
            "thin_protocol_takeover",
            "protocol_takeover_v2",
            "takeover_v2",
        }
        protocol_takeover = signup_mode in protocol_takeover_modes
        fast_fill = signup_mode in {
            "fast_dom",
            "semi_protocol",
            "semiprotocol",
            "protocol_assist",
            "protocol_takeover",
            "protocol_takeover_v1",
            "protocol_takeover_thin",
            "thin_protocol_takeover",
            "protocol_takeover_v2",
            "takeover_v2",
            "takeover_v1",
            "protocol_v1",
        }
        protocol_assist = signup_mode in {
            "protocol_assist",
            "protocol_takeover",
            "protocol_takeover_v1",
            "protocol_takeover_thin",
            "thin_protocol_takeover",
            "protocol_takeover_v2",
            "takeover_v2",
            "takeover_v1",
            "protocol_v1",
        }
        if fast_fill:
            print(
                f"[SemiProtocolFill] enabled mode={getattr(self, 'signup_fill_mode', 'fast_dom')} "
                "strategy="
                + (
                    (
                        "protocol-takeover-v2-thin; minimal bootstrap -> challenge shell"
                        if protocol_takeover_thin
                        else "protocol-takeover-v1; browser/profile/captcha shell unchanged"
                    )
                    if protocol_takeover
                    else "browser-session+direct DOM state; captcha/profile flow unchanged"
                ),
                flush=True,
            )

        fill_phase_t0 = time.time()
        fill_phase_last = fill_phase_t0

        def mark_fill_phase(label, extra=""):
            nonlocal fill_phase_last
            if not fast_fill:
                return
            now = time.time()
            delta = (now - fill_phase_last) * 1000
            total = (now - fill_phase_t0) * 1000
            fill_phase_last = now
            suffix = f" {extra}" if extra else ""
            print(
                f"[SemiProtocolFillTiming] {label} +{delta:.0f}ms total={total:.0f}ms{suffix}",
                flush=True,
            )

        def random_lower_name(default_min=3, default_max=5):
            length_spec = fill_profile.get("name_length", [default_min, default_max])
            try:
                if isinstance(length_spec, list) and len(length_spec) >= 2:
                    n = random.randint(int(length_spec[0]), int(length_spec[1]))
                else:
                    n = int(length_spec)
            except Exception:
                n = random.randint(default_min, default_max)
            alphabet = "abcdefghijklmnopqrstuvwxyz"
            return "".join(random.choice(alphabet) for _ in range(max(1, n)))

        if fill_profile.get("first_name") or fill_profile.get("last_name"):
            firstname = str(fill_profile.get("first_name") or random_lower_name())
            lastname = str(fill_profile.get("last_name") or random_lower_name())
        elif str(fill_profile.get("name_mode") or "").lower() in {"short_lower", "success_sample", "sample"}:
            firstname = random_lower_name()
            lastname = random_lower_name()
        elif Faker:
            fake = Faker()
            lastname = fake.last_name()
            firstname = fake.first_name()
        else:
            # CTF/offline fallback: keep the flow usable when faker is not
            # installed in the sandbox. Outlook accepts simple latin names.
            lastname = random.choice(["Smith", "Johnson", "Williams", "Brown", "Jones"])
            firstname = random.choice(["Alex", "Chris", "Taylor", "Jordan", "Morgan"])

        birth_mode = str(fill_profile.get("birth_mode") or fill_profile.get("dob_mode") or "").lower()
        if birth_mode in {"random", "original", "original_random"}:
            year = str(random.randint(1960, 2005))
            month = str(random.randint(1, 12))
            day = str(random.randint(1, 28))
        else:
            year = str(fill_profile.get("birth_year") or random.randint(1960, 2005))
            # The current Fluent DOB form can intermittently reset the day combo
            # after month/year changes.  Keep month/day simple and stable for live
            # protocol tests so we do not burn IPs on a front-end form race.
            month = str(fill_profile.get("birth_month") or "1")
            day = str(fill_profile.get("birth_day") or "1")

        def finalize_registration_success():
            filename = os.path.join(self.results_dir, 'logged_email.txt' if self.enable_oauth2 else 'unlogged_email.txt')
            with open(filename, 'a', encoding='utf-8') as f:
                f.write(f"{email}{self.email_suffix}: {password}\n")
            print(f'[Success: Email Registration] - {email}{self.email_suffix}: {password}')

            if not self.enable_oauth2:
                return True

            try:
                page.locator('[aria-label="新邮件"]').wait_for(timeout=32000)
                return True
            except:
                print('[Error: Timeout] - 邮箱未初始化，无法正常收件。')
                return False

        self.attach_network_logger(page, email)

        def install_early_risk_initialize_protocol_observer():
            cache = {
                "ready": False,
                "observed": False,
                "used": 0,
                "status": 0,
                "body": "",
                "headers": {},
                "allow_fulfill": False,
            }
            try:
                def summarize_risk_initialize_body(body):
                    try:
                        parsed = json.loads(body or "{}")
                    except Exception:
                        parsed = {}
                    providers = []
                    human_url = ""
                    try:
                        for item in parsed.get("riskInitializationData") or []:
                            if isinstance(item, dict):
                                provider = item.get("riskProvider")
                                if provider:
                                    providers.append(provider)
                                if not human_url and item.get("humanSensorUrl"):
                                    human_url = str(item.get("humanSensorUrl") or "")
                    except Exception:
                        pass
                    return {
                        "state": parsed.get("state") if isinstance(parsed, dict) else None,
                        "hasContinuationToken": bool(
                            isinstance(parsed, dict) and parsed.get("continuationToken")
                        ),
                        "continuationLen": len(str(parsed.get("continuationToken") or ""))
                            if isinstance(parsed, dict) else 0,
                        "providers": providers,
                        "hasHumanSensorUrl": bool(human_url),
                        "humanSensorUrlPrefix": human_url[:96],
                    }

                def on_risk_initialize_response(response):
                    try:
                        request = getattr(response, "request", None)
                        url = str(getattr(response, "url", "") or "")
                        method = str(getattr(request, "method", "") or "")
                        if "api/v1.0/risk/initialize" not in url or method != "POST":
                            return
                        if cache.get("observed"):
                            return
                        started = time.time()
                        body = response.text()
                        headers = dict(getattr(response, "headers", {}) or {})
                        cache.update(
                            {
                                "ready": True,
                                "observed": True,
                                "status": int(getattr(response, "status", 0) or 0),
                                "body": body,
                                "headers": headers or {"content-type": "application/json; charset=utf-8"},
                                "responseSummary": summarize_risk_initialize_body(body),
                                "read_ms": round((time.time() - started) * 1000, 1),
                            }
                        )
                        print(
                            "[SemiProtocolFill] risk/initialize observed via response listener "
                            f"status={cache.get('status')} read_ms={cache.get('read_ms')} "
                            f"summary={cache.get('responseSummary')}",
                            flush=True,
                        )
                    except Exception as exc:
                        print(f"[SemiProtocolFill] risk/initialize response observer failed: {exc!r}", flush=True)

                page.on("response", on_risk_initialize_response)
                cache["response_listener"] = on_risk_initialize_response
                print("[SemiProtocolFill] risk/initialize early response observer installed", flush=True)
                return cache
            except Exception as exc:
                print(f"[SemiProtocolFill] risk/initialize early response observer install failed: {exc!r}", flush=True)
                return cache

        risk_initialize_cache = None
        if protocol_assist:
            risk_initialize_cache = install_early_risk_initialize_protocol_observer()

        def signup_email_entry_visible(timeout=1000):
            """True when the first signup page is already showing the email-name field.

            JA-JP and other localized pages can skip the Chinese "同意并继续"
            gate and land directly on "Microsoft アカウントの作成".  Treat that
            as a valid entry instead of burning the run as an IP failure.
            """
            try:
                page.wait_for_function(
                    """() => {
                        const visible = (el) => {
                            if (!el) return false;
                            const r = el.getBoundingClientRect?.();
                            const s = getComputedStyle(el);
                            return !!r && r.width > 0 && r.height > 0 &&
                                s.visibility !== 'hidden' && s.display !== 'none';
                        };
                        const inputs = [...document.querySelectorAll('input')]
                            .filter(visible)
                            .filter(el => {
                                const type = String(el.getAttribute('type') || 'text').toLowerCase();
                                if (['hidden', 'password', 'checkbox', 'radio', 'submit', 'button'].includes(type)) return false;
                                const meta = [
                                    el.name, el.id, el.getAttribute('aria-label'),
                                    el.getAttribute('placeholder'), el.autocomplete
                                ].filter(Boolean).join(' ').toLowerCase();
                                return /mail|email|member|sign|login|メール|アドレス|電子|邮箱|郵箱|邮件|郵件/.test(meta) ||
                                    document.body.innerText.includes('@outlook.');
                            });
                        return inputs.length > 0 && document.body.innerText.includes('@outlook');
                    }""",
                    timeout=timeout,
                )
                return True
            except Exception:
                return False

        def accept_initial_consent_gate(timeout_ms=30000):
            """Click the first Microsoft consent/transfer gate on a fresh profile."""
            deadline = time.time() + max(1000, int(timeout_ms)) / 1000
            while time.time() < deadline:
                if signup_email_entry_visible(timeout=500):
                    return True
                try:
                    clicked = page.evaluate(
                        r"""() => {
                            const visible = (el) => {
                                if (!el) return false;
                                const r = el.getBoundingClientRect?.();
                                const s = getComputedStyle(el);
                                return !!r && r.width > 0 && r.height > 0 &&
                                    s.visibility !== 'hidden' && s.display !== 'none' &&
                                    !el.disabled && el.getAttribute('aria-disabled') !== 'true';
                            };
                            const norm = (s) => String(s || '').replace(/\s+/g, '').toLowerCase();
                            const fire = (el) => {
                                try { el.scrollIntoView({block:'center', inline:'center'}); } catch (_) {}
                                try { el.focus?.(); } catch (_) {}
                                try { el.dispatchEvent(new MouseEvent('mouseover', {bubbles:true})); } catch (_) {}
                                try { el.dispatchEvent(new MouseEvent('mousedown', {bubbles:true})); } catch (_) {}
                                try { el.click(); } catch (_) {}
                                try { el.dispatchEvent(new MouseEvent('mouseup', {bubbles:true})); } catch (_) {}
                            };
                            const primary = document.querySelector('[data-testid="primaryButton"]');
                            if (visible(primary)) {
                                fire(primary);
                                return 'primaryButton';
                            }
                            const allow = ['\u540c\u610f', '\u7ee7\u7eed', 'accept', 'agree', 'continue'];
                            const deny = ['\u62d2\u7edd', 'decline', 'reject', 'exit'];
                            const nodes = [...document.querySelectorAll(
                                'button,[role="button"],input[type="button"],input[type="submit"]'
                            )].filter(visible);
                            for (const el of nodes) {
                                const text = norm(el.innerText || el.value || el.getAttribute('aria-label') || el.textContent);
                                if (!text) continue;
                                if (deny.some(x => text.includes(x))) continue;
                                if (allow.some(x => text.includes(x))) {
                                    fire(el);
                                    return text.slice(0, 80);
                                }
                            }
                            return '';
                        }"""
                    )
                    if clicked:
                        page.wait_for_timeout(1200)
                        continue
                except Exception:
                    pass
                try:
                    page.wait_for_timeout(500)
                except Exception:
                    time.sleep(0.5)
            return signup_email_entry_visible(timeout=1000)

        def thin_protocol_bootstrap_state():
            """Minimal state probe for V2 before the full signup UI is visible.

            V1/V2 only need the page canary plus uaid/search tuple to build the
            early risk chain.  Waiting for the visible email field burns time on
            slow bundles, so the thin path polls these bootstrap artifacts
            directly after navigation commit.
            """
            try:
                return page.evaluate(
                    r"""() => {
                        const addCandidate = (arr, value) => {
                            if (typeof value !== 'string') return;
                            const v = value.trim();
                            if (v.length >= 20 && !arr.includes(v)) arr.push(v);
                        };
                        const decodeJsString = (s) => {
                            try { return JSON.parse('"' + String(s).replace(/"/g, '\\"') + '"'); }
                            catch (_) { return s; }
                        };
                        const findCanary = () => {
                            const candidates = [];
                            for (const sel of [
                                'input[name="apiCanary"]',
                                'input[name="canary"]',
                                'input[name="Canary"]',
                                'meta[name="apiCanary"]',
                                'meta[name="canary"]'
                            ]) {
                                const el = document.querySelector(sel);
                                addCandidate(candidates, el?.value || el?.content || el?.getAttribute?.('content'));
                            }
                            try {
                                const keys = Object.keys(window).slice(0, 900);
                                for (const k of keys) {
                                    let v;
                                    try { v = window[k]; } catch (_) { continue; }
                                    if (/canary|apiCanary/i.test(k)) addCandidate(candidates, v);
                                    if (v && typeof v === 'object') {
                                        for (const kk of Object.keys(v).slice(0, 120)) {
                                            if (!/canary|apiCanary/i.test(kk)) continue;
                                            try { addCandidate(candidates, v[kk]); } catch (_) {}
                                        }
                                    }
                                }
                            } catch (_) {}
                            try {
                                const text = [...document.scripts].map(s => s.textContent || '').join('\n').slice(0, 4000000);
                                const patterns = [
                                    /"apiCanary"\s*:\s*"([^"]{40,})"/i,
                                    /"canary"\s*:\s*"([^"]{40,})"/i,
                                    /apiCanary\s*[:=]\s*['"]([^'"]{40,})['"]/i,
                                    /canary\s*[:=]\s*['"]([^'"]{40,})['"]/i
                                ];
                                for (const re of patterns) {
                                    const m = text.match(re);
                                    if (m) addCandidate(candidates, decodeJsString(m[1]));
                                }
                            } catch (_) {}
                            return candidates[0] || '';
                        };
                        const pageUrl = new URL(location.href);
                        const rawQuery = location.search || '';
                        const rawSruMatch = rawQuery.match(/[?&]sru=([^&]+)/i);
                        const signupReturnUrl = rawSruMatch ? rawSruMatch[1] : '';
                        const sruRaw = pageUrl.searchParams.get('sru') || '';
                        let uaid = pageUrl.searchParams.get('uaid') || '';
                        try {
                            if (sruRaw) {
                                const sruUrl = new URL(decodeURIComponent(sruRaw));
                                uaid = uaid || sruUrl.searchParams.get('uaid') || '';
                            }
                        } catch (_) {}
                        return {
                            href: location.href,
                            origin: location.origin,
                            search: location.search || '',
                            canary: findCanary(),
                            uaid,
                            signupReturnUrl,
                            readyState: document.readyState,
                            inputCount: document.querySelectorAll('input').length,
                            scriptCount: document.scripts.length,
                        };
                    }"""
                )
            except Exception as exc:
                return {"ok": False, "reason": repr(exc)[:180]}

        def wait_thin_protocol_bootstrap(timeout_ms=None):
            timeout_ms = int(
                timeout_ms
                if timeout_ms is not None
                else getattr(self, "signup_protocol_takeover_thin_bootstrap_wait_ms", 12000)
            )
            deadline = time.time() + max(500, timeout_ms) / 1000.0
            last_state = {}
            while time.time() < deadline:
                last_state = thin_protocol_bootstrap_state() or {}
                if (
                    str(last_state.get("origin") or "").startswith("https://signup.live.com")
                    and last_state.get("canary")
                    and last_state.get("uaid")
                ):
                    return {"ok": True, "state": last_state}
                try:
                    page.wait_for_timeout(200)
                except Exception:
                    time.sleep(0.2)
            return {"ok": False, "state": last_state}

        start_time = time.time()
        try:
            entry_url = self.signup_entry_url or "https://outlook.live.com/mail/0/?prompt=create_account"
            goto_wait_until = "domcontentloaded"
            if protocol_takeover_thin:
                goto_wait_until = str(
                    getattr(self, "signup_protocol_takeover_thin_goto_wait_until", "commit") or "commit"
                ).strip().lower()
                if goto_wait_until not in {"commit", "domcontentloaded", "load", "networkidle"}:
                    goto_wait_until = "commit"
            page.goto(entry_url, timeout=20000, wait_until=goto_wait_until)
            thin_bootstrap = {"ok": False, "state": {}}
            if protocol_takeover_thin:
                thin_bootstrap = wait_thin_protocol_bootstrap()
                if not thin_bootstrap.get("ok"):
                    accept_initial_consent_gate(timeout_ms=3500)
                    thin_bootstrap = wait_thin_protocol_bootstrap(timeout_ms=4500)
                print(
                    "[ProtocolTakeoverV2] thin bootstrap "
                    f"ok={thin_bootstrap.get('ok')} "
                    f"readyState={(thin_bootstrap.get('state') or {}).get('readyState')} "
                    f"has_canary={bool((thin_bootstrap.get('state') or {}).get('canary'))} "
                    f"uaid={(thin_bootstrap.get('state') or {}).get('uaid')} "
                    f"href={str((thin_bootstrap.get('state') or {}).get('href') or '')[:120]}",
                    flush=True,
                )
            if not protocol_takeover_thin and not signup_email_entry_visible(timeout=2500):
                start_time = time.time()
                page.wait_for_timeout(0.1 * self.wait_time)
                accept_initial_consent_gate(timeout_ms=30000)
                signup_email_entry_visible(timeout=15000)
            elif protocol_takeover_thin and not thin_bootstrap.get("ok"):
                # Preserve recoverability: if the thin artifact probe misses,
                # fall back to the older visible-entry readiness rather than
                # burning the run as an immediate failure.
                print("[ProtocolTakeoverV2] thin bootstrap fallback to visible entry wait", flush=True)
                if not signup_email_entry_visible(timeout=2500):
                    page.wait_for_timeout(0.1 * self.wait_time)
                    accept_initial_consent_gate(timeout_ms=10000)
                    signup_email_entry_visible(timeout=8000)
        except:
            if not signup_email_entry_visible(timeout=1500):
                print("[Error: IP] - IP质量不佳，无法进入注册界面。")
                self.save_diagnostic(page, "entry_failed", email)
                return False

        mark_fill_phase("entry_ready")

        try:
            primary_click_counter = {"n": 0}

            def click_primary_button(timeout=10000, force_native=False, purpose=""):
                primary_click_counter["n"] = int(primary_click_counter.get("n") or 0) + 1
                click_no = primary_click_counter["n"]
                submit_mode = str(getattr(self, "signup_submit_mode", "dom_fast") or "dom_fast").lower()
                if force_native:
                    submit_mode = "native"
                if fast_fill and submit_mode not in {"native", "playwright", "ui"}:
                    started = time.time()
                    fast_budget_ms = max(
                        100,
                        min(int(timeout or 0), int(getattr(self, "signup_submit_fast_wait_ms", 1800) or 1800)),
                    )
                    deadline = started + fast_budget_ms / 1000.0
                    last_result = None
                    while time.time() < deadline:
                        try:
                            last_result = page.evaluate(
                                """() => {
                                    const visible = (el) => {
                                        if (!el) return false;
                                        const r = el.getBoundingClientRect?.();
                                        const s = getComputedStyle(el);
                                        return !!r && r.width > 0 && r.height > 0 &&
                                            s.visibility !== 'hidden' && s.display !== 'none';
                                    };
                                    const textOf = (el) => String(
                                        el?.innerText || el?.textContent || el?.value ||
                                        el?.getAttribute?.('aria-label') || ''
                                    ).replace(/\\s+/g, ' ').trim();
                                    const candidates = [
                                        document.querySelector('[data-testid="primaryButton"]'),
                                        document.querySelector('button[type="submit"]'),
                                        document.querySelector('input[type="submit"]'),
                                        ...document.querySelectorAll('button, [role="button"]')
                                    ].filter(Boolean);
                                    const seen = new Set();
                                    const buttons = candidates.filter((el) => {
                                        if (seen.has(el)) return false;
                                        seen.add(el);
                                        return visible(el);
                                    });
                                    const btn = buttons.find((el) => {
                                        const t = textOf(el);
                                        return el.matches?.('[data-testid="primaryButton"], button[type="submit"], input[type="submit"]') ||
                                            /^(next|continue|create|sign up|verify|下一步|继续|创建|同意)/i.test(t);
                                    }) || null;
                                    if (!btn) return {ok: false, reason: 'button_not_found', visible: buttons.map(textOf).slice(0, 8)};
                                    const disabled = !!btn.disabled || btn.getAttribute('aria-disabled') === 'true' ||
                                        btn.matches?.('[disabled], [aria-disabled="true"]');
                                    if (disabled) return {ok: false, reason: 'button_disabled', text: textOf(btn).slice(0, 80)};
                                    btn.scrollIntoView({block: 'center', inline: 'center'});
                                    try { btn.focus({preventScroll: true}); } catch (_) { try { btn.focus(); } catch (_) {} }
                                    btn.click();
                                    return {ok: true, text: textOf(btn).slice(0, 80)};
                                }"""
                            )
                            if isinstance(last_result, dict) and last_result.get("ok"):
                                elapsed_ms = (time.time() - started) * 1000
                                print(
                                    f"[SemiProtocolFillClick] #{click_no} mode=dom_fast ms={elapsed_ms:.0f} "
                                    f"purpose={purpose or '-'} text={str(last_result.get('text') or '')[:60]!r}",
                                    flush=True,
                                )
                                return True
                        except Exception as exc:
                            last_result = {"ok": False, "reason": repr(exc)[:160]}
                            break
                        page.wait_for_timeout(60)
                    print(
                        f"[SemiProtocolFillClick] #{click_no} mode=dom_fast fallback "
                        f"after_ms={(time.time() - started) * 1000:.0f} last={last_result}",
                        flush=True,
                    )
                try:
                    native_started = time.time()
                    page.locator('[data-testid="primaryButton"]').click(timeout=timeout)
                    if fast_fill:
                        print(
                            f"[SemiProtocolFillClick] #{click_no} mode=native ms={(time.time() - native_started) * 1000:.0f} "
                            f"purpose={purpose or '-'}",
                            flush=True,
                        )
                    return True
                except Exception:
                    # CloakBrowser humanization can make Playwright report a
                    # click timeout even though the page accepts it a moment
                    # later.  Fire the DOM click as a fallback and let the next
                    # explicit page-state wait decide whether it worked.
                    try:
                        fallback_started = time.time()
                        fallback_ok = bool(page.evaluate(
                            """() => {
                                const btn = document.querySelector('[data-testid="primaryButton"]');
                                const fallback = btn || [...document.querySelectorAll('button, [role="button"], input[type="submit"]')]
                                    .find((el) => {
                                        const r = el.getBoundingClientRect?.();
                                        const s = getComputedStyle(el);
                                        return r && r.width > 0 && r.height > 0 &&
                                            s.visibility !== 'hidden' && s.display !== 'none' &&
                                            !el.disabled && el.getAttribute('aria-disabled') !== 'true';
                                    });
                                if (!fallback) return false;
                                fallback.scrollIntoView({block:'center', inline:'center'});
                                fallback.click();
                                return true;
                            }"""
                        ))
                        if fast_fill:
                            print(
                                f"[SemiProtocolFillClick] #{click_no} mode=dom_fallback "
                                f"ms={(time.time() - fallback_started) * 1000:.0f} purpose={purpose or '-'} ok={fallback_ok}",
                                flush=True,
                            )
                        return fallback_ok
                    except Exception:
                        return False

            def hs_challenge_visible():
                selectors = [
                    'iframe[src*="iframe.hsprotect.net"][src*="ch_ctx=1"]',
                    'iframe[title="验证质询"]',
                    'iframe#enforcementFrame',
                ]
                for selector in selectors:
                    try:
                        if page.locator(selector).count() > 0:
                            return True
                    except Exception:
                        continue
                return False

            def create_account_requested_or_done():
                state = self.get_create_account_state(page)
                return bool(state.get("create_success") or int(state.get("create_requests") or 0) > 0)

            def wait_after_name_submit(timeout_ms=12000):
                deadline = time.time() + max(1000, int(timeout_ms or 0)) / 1000
                left_name_seen_at = None
                left_name_grace_s = (
                    max(500, int(getattr(self, "signup_fast_left_name_page_ms", 10000) or 10000)) / 1000.0
                    if fast_fill
                    else 10.0
                )
                poll_ms = (
                    max(60, int(getattr(self, "signup_fast_name_submit_poll_ms", 350) or 350))
                    if fast_fill
                    else 350
                )
                while time.time() < deadline:
                    if create_account_requested_or_done():
                        return "create_account"
                    try:
                        state = self.get_create_account_state(page)
                        if state.get("riskblock"):
                            return "blocked"
                    except Exception:
                        pass
                    if hs_challenge_visible():
                        return "challenge"
                    if page.get_by_text('账户创建已被阻止').count() or page.get_by_text('一些异常活动').count():
                        return "blocked"
                    try:
                        if page.locator('#lastNameInput').count() == 0 and page.locator('#firstNameInput').count() == 0:
                            if left_name_seen_at is None:
                                left_name_seen_at = time.time()
                            # Leaving the name page usually precedes the
                            # ch_ctx=1 hsprotect iframe by 1-3s.  Do not start
                            # captcha automation against the old non-challenge
                            # iframe too early.
                            if time.time() - left_name_seen_at >= left_name_grace_s:
                                return "left_name_page"
                        else:
                            left_name_seen_at = None
                    except Exception:
                        if left_name_seen_at is None:
                            left_name_seen_at = time.time()
                        if time.time() - left_name_seen_at >= left_name_grace_s:
                            return "left_name_page"
                    page.wait_for_timeout(poll_ms)
                return "timeout"

            def set_email_suffix(suffix):
                suffix = str(suffix or "").strip()
                if not suffix:
                    return {"ok": False, "reason": "empty"}
                try:
                    opened = page.evaluate(
                        """(suffix) => {
                            const visible = (el) => {
                                if (!el) return false;
                                const r = el.getBoundingClientRect?.();
                                const s = getComputedStyle(el);
                                return !!r && r.width > 0 && r.height > 0 &&
                                    s.visibility !== 'hidden' && s.display !== 'none';
                            };
                            const clean = (s) => String(s || '').replace(/\\s+/g, ' ').trim();
                            const clickNative = (el) => {
                                el.scrollIntoView({block: 'center', inline: 'center'});
                                el.dispatchEvent(new MouseEvent('mouseover', {bubbles: true}));
                                el.dispatchEvent(new MouseEvent('mousedown', {bubbles: true}));
                                el.click();
                                el.dispatchEvent(new MouseEvent('mouseup', {bubbles: true}));
                            };
                            const textOf = (el) => clean([
                                el.innerText, el.textContent, el.getAttribute('aria-label'),
                                el.getAttribute('title'), el.value
                            ].filter(Boolean).join(' '));
                            for (const sel of [...document.querySelectorAll('select')].filter(visible)) {
                                const opts = [...(sel.options || [])];
                                const match = opts.find(o => clean(o.textContent) === suffix || String(o.value || '') === suffix);
                                if (match) {
                                    const previous = sel.value;
                                    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set;
                                    if (setter) setter.call(sel, match.value); else sel.value = match.value;
                                    try { sel._valueTracker && sel._valueTracker.setValue(previous); } catch (_) {}
                                    sel.dispatchEvent(new Event('input', {bubbles: true}));
                                    sel.dispatchEvent(new Event('change', {bubbles: true}));
                                    sel.dispatchEvent(new Event('blur', {bubbles: true}));
                                    return {ok: true, via: 'select', text: clean(match.textContent), value: sel.value};
                                }
                            }
                            const controls = [...document.querySelectorAll(
                                'button, [role="button"], [role="combobox"], [aria-haspopup], [data-testid]'
                            )].filter(visible);
                            const exact = controls.find(el => textOf(el) === suffix);
                            if (exact) return {ok: true, via: 'already', text: textOf(exact)};
                            const current = controls.find(el => /@outlook\\.|@hotmail\\./i.test(textOf(el)));
                            if (!current) return {ok: false, reason: 'suffix_control_not_found', visible: controls.map(textOf).filter(Boolean).slice(0, 20)};
                            clickNative(current);
                            return {ok: true, via: 'opened', current: textOf(current)};
                        }""",
                        suffix,
                    )
                    if isinstance(opened, dict) and opened.get("via") == "opened":
                        page.wait_for_timeout(450)
                        chosen = page.evaluate(
                            """(suffix) => {
                                const visible = (el) => {
                                    if (!el) return false;
                                    const r = el.getBoundingClientRect?.();
                                    const s = getComputedStyle(el);
                                    return !!r && r.width > 0 && r.height > 0 &&
                                        s.visibility !== 'hidden' && s.display !== 'none';
                                };
                                const clean = (s) => String(s || '').replace(/\\s+/g, ' ').trim();
                                const textOf = (el) => clean(el.innerText || el.textContent || el.getAttribute('aria-label') || el.value || '');
                                const nodes = [...document.querySelectorAll('[role="option"], [role="menuitem"], button, div, span')]
                                    .filter(visible);
                                const match = nodes.find(el => textOf(el) === suffix) ||
                                    nodes.find(el => textOf(el).includes(suffix));
                                if (!match) return {ok: false, reason: 'suffix_option_not_found', visible: nodes.map(textOf).filter(Boolean).slice(0, 30)};
                                match.scrollIntoView({block: 'center', inline: 'center'});
                                match.dispatchEvent(new MouseEvent('mouseover', {bubbles: true}));
                                match.dispatchEvent(new MouseEvent('mousedown', {bubbles: true}));
                                match.click();
                                match.dispatchEvent(new MouseEvent('mouseup', {bubbles: true}));
                                return {ok: true, text: textOf(match)};
                            }""",
                            suffix,
                        )
                        if isinstance(chosen, dict) and chosen.get("ok"):
                            return chosen
                        opened["option_result"] = chosen
                    return opened
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:180]}

            def fill_signup_email(value):
                value = str(value or "")
                try:
                    return page.evaluate(
                        """(value) => {
                            const visible = (el) => {
                                if (!el) return false;
                                const r = el.getBoundingClientRect?.();
                                const s = getComputedStyle(el);
                                return !!r && r.width > 0 && r.height > 0 &&
                                    s.visibility !== 'hidden' && s.display !== 'none';
                            };
                            const score = (el) => {
                                const meta = [
                                    el.name, el.id, el.getAttribute('aria-label'),
                                    el.getAttribute('placeholder'), el.autocomplete,
                                    el.closest('label')?.innerText
                                ].filter(Boolean).join(' ').toLowerCase();
                                let s = 0;
                                if (/member|signin|login|email|mail|メール|アドレス|電子|邮箱|郵箱|邮件|郵件/.test(meta)) s += 20;
                                if (/birth|year|month|day|first|last|name|country|region|password/.test(meta)) s -= 50;
                                const r = el.getBoundingClientRect();
                                s += Math.max(0, 600 - Math.abs(r.top - 350)) / 100;
                                return s;
                            };
                            const candidates = [...document.querySelectorAll('input')]
                                .filter(visible)
                                .filter(el => {
                                    const type = String(el.getAttribute('type') || 'text').toLowerCase();
                                    return !['hidden', 'password', 'checkbox', 'radio', 'submit', 'button'].includes(type);
                                })
                                .sort((a, b) => score(b) - score(a));
                            const el = candidates[0];
                            if (!el) return {ok: false, reason: 'email_input_not_found'};
                            el.scrollIntoView({block: 'center', inline: 'center'});
                            el.focus();
                            const previous = el.value;
                            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
                            if (setter) setter.call(el, value); else el.value = value;
                            try { el._valueTracker && el._valueTracker.setValue(previous); } catch (_) {}
                            el.dispatchEvent(new InputEvent('input', {bubbles: true, inputType: 'insertText', data: value}));
                            el.dispatchEvent(new Event('change', {bubbles: true}));
                            el.dispatchEvent(new Event('blur', {bubbles: true}));
                            return {
                                ok: String(el.value || '') === value,
                                value: el.value,
                                name: el.name || '',
                                id: el.id || '',
                                aria: el.getAttribute('aria-label') || '',
                                placeholder: el.getAttribute('placeholder') || ''
                            };
                        }""",
                        value,
                    )
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:180]}

            def install_check_available_protocol_cache():
                """
                Phase-B semi-protocol assist:
                prefetch CheckAvailableSigninNames from inside the live signup
                page, then fulfill the UI's later identical request from the
                cached body.  This keeps cookies/canary/browser headers bound to
                the real profile and does not bypass the later HS/risk flow.
                """
                cache = {"ready": False, "used": 0, "status": 0, "body": "", "headers": {}}
                try:
                    def check_available_route(route, request):
                        try:
                            headers = getattr(request, "headers", {}) or {}
                            if str(headers.get("x-outlook-register-prefetch") or "").strip() == "1":
                                return route.continue_()
                            if (
                                cache.get("ready")
                                and request.method == "POST"
                                and cache.get("body")
                            ):
                                cache["used"] = int(cache.get("used") or 0) + 1
                                print(
                                    "[SemiProtocolFill] CheckAvailable fulfill from protocol cache "
                                    f"status={cache.get('status')} used={cache.get('used')}",
                                    flush=True,
                                )
                                return route.fulfill(
                                    status=int(cache.get("status") or 200),
                                    headers=cache.get("headers") or {"content-type": "application/json; charset=utf-8"},
                                    body=str(cache.get("body") or ""),
                                )
                            return route.continue_()
                        except Exception as exc:
                            print(f"[SemiProtocolFill] CheckAvailable route fallback: {exc!r}", flush=True)
                            try:
                                return route.continue_()
                            except Exception:
                                return None

                    page.route("**/API/CheckAvailableSigninNames*", check_available_route)
                    print("[SemiProtocolFill] CheckAvailable protocol cache route installed", flush=True)
                    return cache
                except Exception as exc:
                    print(f"[SemiProtocolFill] CheckAvailable route install failed: {exc!r}", flush=True)
                    return cache

            check_available_cache = None
            protocol_assist = signup_mode in {
                "protocol_assist",
                "protocol_takeover",
                "protocol_takeover_v1",
                "protocol_takeover_thin",
                "thin_protocol_takeover",
                "protocol_takeover_v2",
                "takeover_v2",
                "takeover_v1",
                "protocol_v1",
            }
            if protocol_assist:
                check_available_cache = install_check_available_protocol_cache()

            def install_risk_initialize_protocol_cache():
                cache = {
                    "ready": False,
                    "observed": False,
                    "used": 0,
                    "status": 0,
                    "body": "",
                    "headers": {},
                    "allow_fulfill": False,
                }
                try:
                    def summarize_risk_initialize_body(body):
                        try:
                            parsed = json.loads(body or "{}")
                        except Exception:
                            parsed = {}
                        providers = []
                        human_url = ""
                        try:
                            for item in parsed.get("riskInitializationData") or []:
                                if isinstance(item, dict):
                                    provider = item.get("riskProvider")
                                    if provider:
                                        providers.append(provider)
                                    if not human_url and item.get("humanSensorUrl"):
                                        human_url = str(item.get("humanSensorUrl") or "")
                        except Exception:
                            pass
                        return {
                            "state": parsed.get("state") if isinstance(parsed, dict) else None,
                            "hasContinuationToken": bool(
                                isinstance(parsed, dict) and parsed.get("continuationToken")
                            ),
                            "continuationLen": len(str(parsed.get("continuationToken") or ""))
                                if isinstance(parsed, dict) else 0,
                            "providers": providers,
                            "hasHumanSensorUrl": bool(human_url),
                            "humanSensorUrlPrefix": human_url[:96],
                        }

                    def risk_initialize_route(route, request):
                        try:
                            if cache.get("prefetch_inflight"):
                                return route.continue_()
                            if (
                                cache.get("ready")
                                and cache.get("allow_fulfill")
                                and request.method == "POST"
                                and cache.get("body")
                            ):
                                cache["used"] = int(cache.get("used") or 0) + 1
                                print(
                                    "[SemiProtocolFill] risk/initialize fulfill from protocol cache "
                                    f"status={cache.get('status')} used={cache.get('used')}",
                                    flush=True,
                                )
                                return route.fulfill(
                                    status=int(cache.get("status") or 200),
                                    headers=cache.get("headers") or {"content-type": "application/json; charset=utf-8"},
                                    body=str(cache.get("body") or ""),
                                )
                            if request.method == "POST":
                                # Phase-C safe mode: do not duplicate the cross-origin
                                # risk/initialize fetch.  Instead, let the browser's
                                # natural request happen through route.fetch(), cache
                                # the exact body/headers for analysis, then fulfill
                                # the page with the same response.  This gives us
                                # continuationToken / hsprotect bootstrap data without
                                # changing the state machine or adding an extra request.
                                started = time.time()
                                response = route.fetch()
                                body = response.text()
                                headers = dict(getattr(response, "headers", {}) or {})
                                cache.update(
                                    {
                                        "ready": True,
                                        "observed": True,
                                        "status": int(getattr(response, "status", 0) or 0),
                                        "body": body,
                                        "headers": headers or {"content-type": "application/json; charset=utf-8"},
                                        "responseSummary": summarize_risk_initialize_body(body),
                                        "route_fetch_ms": round((time.time() - started) * 1000, 1),
                                    }
                                )
                                print(
                                    "[SemiProtocolFill] risk/initialize observed via route.fetch "
                                    f"status={cache.get('status')} ms={cache.get('route_fetch_ms')} "
                                    f"summary={cache.get('responseSummary')}",
                                    flush=True,
                                )
                                return route.fulfill(response=response, body=body)
                            return route.continue_()
                        except Exception as exc:
                            print(f"[SemiProtocolFill] risk/initialize route fallback: {exc!r}", flush=True)
                            try:
                                return route.continue_()
                            except Exception:
                                return None

                    page.route("**/api/v1.0/risk/initialize*", risk_initialize_route)
                    print("[SemiProtocolFill] risk/initialize protocol cache route installed", flush=True)
                    return cache
                except Exception as exc:
                    print(f"[SemiProtocolFill] risk/initialize route install failed: {exc!r}", flush=True)
                    return cache

            try:
                risk_initialize_cache
            except NameError:
                risk_initialize_cache = None
            if protocol_assist and not risk_initialize_cache:
                risk_initialize_cache = install_risk_initialize_protocol_cache()

            def prefetch_risk_initialize_protocol():
                if not risk_initialize_cache:
                    return {"ok": False, "reason": "cache_not_installed"}
                try:
                    risk_initialize_cache["prefetch_inflight"] = True
                    result = page.evaluate(
                        """async () => {
                            const addCandidate = (arr, value) => {
                                if (typeof value !== 'string') return;
                                const v = value.trim();
                                if (v.length >= 40 && !arr.includes(v)) arr.push(v);
                            };
                            const decodeJsString = (s) => {
                                try { return JSON.parse('"' + String(s).replace(/"/g, '\\"') + '"'); }
                                catch (_) { return s; }
                            };
                            const findCanary = () => {
                                const candidates = [];
                                for (const sel of [
                                    'input[name="apiCanary"]',
                                    'input[name="canary"]',
                                    'input[name="Canary"]',
                                    'meta[name="apiCanary"]',
                                    'meta[name="canary"]'
                                ]) {
                                    const el = document.querySelector(sel);
                                    addCandidate(candidates, el?.value || el?.content || el?.getAttribute?.('content'));
                                }
                                try {
                                    const keys = Object.keys(window).slice(0, 600);
                                    for (const k of keys) {
                                        let v;
                                        try { v = window[k]; } catch (_) { continue; }
                                        if (/canary/i.test(k)) addCandidate(candidates, v);
                                        if (v && typeof v === 'object') {
                                            for (const kk of Object.keys(v).slice(0, 80)) {
                                                if (!/canary/i.test(kk)) continue;
                                                try { addCandidate(candidates, v[kk]); } catch (_) {}
                                            }
                                        }
                                    }
                                } catch (_) {}
                                try {
                                    const text = [...document.scripts].map(s => s.textContent || '').join('\\n').slice(0, 3000000);
                                    const patterns = [
                                        /"apiCanary"\\s*:\\s*"([^"]{40,})"/i,
                                        /"canary"\\s*:\\s*"([^"]{40,})"/i,
                                        /apiCanary\\s*[:=]\\s*['"]([^'"]{40,})['"]/i,
                                        /canary\\s*[:=]\\s*['"]([^'"]{40,})['"]/i
                                    ];
                                    for (const re of patterns) {
                                        const m = text.match(re);
                                        if (m) addCandidate(candidates, decodeJsString(m[1]));
                                    }
                                } catch (_) {}
                                return candidates[0] || '';
                            };
                            const pageUrl = new URL(location.href);
                            const sruRaw = pageUrl.searchParams.get('sru') || '';
                            let uaid = pageUrl.searchParams.get('uaid') || '';
                            try {
                                if (sruRaw) {
                                    const sruUrl = new URL(decodeURIComponent(sruRaw));
                                    uaid = uaid || sruUrl.searchParams.get('uaid') || '';
                                }
                            } catch (_) {}
                            const canary = findCanary();
                            if (!canary) {
                                return {ok: false, reason: 'canary_not_found', url: location.href, uaid};
                            }
                            const endpoint = 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/api/v1.0/risk/initialize';
                            const started = performance.now();
                            const resp = await fetch(endpoint, {
                                method: 'POST',
                                credentials: 'include',
                                headers: {
                                    'accept': 'application/json',
                                    'content-type': 'application/json; charset=utf-8',
                                    'canary': canary,
                                    'client-request-id': uaid,
                                    'correlationid': uaid,
                                    'hpgid': '200225',
                                    'hpgact': '0'
                                },
                                body: JSON.stringify({continuationToken: ''})
                            });
                            const text = await resp.text();
                            let parsed = null;
                            try { parsed = JSON.parse(text); } catch (_) {}
                            return {
                                ok: resp.ok && !!parsed && !!parsed.continuationToken,
                                status: resp.status,
                                ms: Math.round((performance.now() - started) * 10) / 10,
                                endpoint,
                                uaid,
                                responseText: text,
                                responseSummary: parsed ? {
                                    state: parsed.state,
                                    hasContinuationToken: !!parsed.continuationToken,
                                    continuationLen: String(parsed.continuationToken || '').length,
                                    providers: Array.isArray(parsed.riskInitializationData)
                                        ? parsed.riskInitializationData.map(x => x && x.riskProvider).filter(Boolean)
                                        : []
                                } : null
                            };
                        }"""
                    )
                    if isinstance(result, dict) and result.get("ok") and result.get("responseText"):
                        risk_initialize_cache.update(
                            {
                                "ready": True,
                                "status": int(result.get("status") or 200),
                                "body": str(result.get("responseText") or ""),
                                "headers": {"content-type": "application/json; charset=utf-8"},
                                "prefetch": result,
                            }
                        )
                    return result
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:240]}
                finally:
                    try:
                        risk_initialize_cache["prefetch_inflight"] = False
                    except Exception:
                        pass

            def prefetch_check_available_protocol(email_full):
                if not check_available_cache:
                    return {"ok": False, "reason": "cache_not_installed"}
                try:
                    result = page.evaluate(
                        """async (emailFull) => {
                            const addCandidate = (arr, value) => {
                                if (typeof value !== 'string') return;
                                const v = value.trim();
                                if (v.length >= 40 && !arr.includes(v)) arr.push(v);
                            };
                            const decodeJsString = (s) => {
                                try { return JSON.parse('"' + String(s).replace(/"/g, '\\"') + '"'); }
                                catch (_) { return s; }
                            };
                            const findCanary = () => {
                                const candidates = [];
                                for (const sel of [
                                    'input[name="apiCanary"]',
                                    'input[name="canary"]',
                                    'input[name="Canary"]',
                                    'meta[name="apiCanary"]',
                                    'meta[name="canary"]'
                                ]) {
                                    const el = document.querySelector(sel);
                                    addCandidate(candidates, el?.value || el?.content || el?.getAttribute?.('content'));
                                }
                                try {
                                    const keys = Object.keys(window).slice(0, 600);
                                    for (const k of keys) {
                                        let v;
                                        try { v = window[k]; } catch (_) { continue; }
                                        if (/canary/i.test(k)) addCandidate(candidates, v);
                                        if (v && typeof v === 'object') {
                                            for (const kk of Object.keys(v).slice(0, 80)) {
                                                if (!/canary/i.test(kk)) continue;
                                                try { addCandidate(candidates, v[kk]); } catch (_) {}
                                            }
                                        }
                                    }
                                } catch (_) {}
                                try {
                                    const text = [...document.scripts].map(s => s.textContent || '').join('\\n').slice(0, 3000000);
                                    const patterns = [
                                        /"apiCanary"\\s*:\\s*"([^"]{40,})"/i,
                                        /"canary"\\s*:\\s*"([^"]{40,})"/i,
                                        /apiCanary\\s*[:=]\\s*['"]([^'"]{40,})['"]/i,
                                        /canary\\s*[:=]\\s*['"]([^'"]{40,})['"]/i
                                    ];
                                    for (const re of patterns) {
                                        const m = text.match(re);
                                        if (m) addCandidate(candidates, decodeJsString(m[1]));
                                    }
                                } catch (_) {}
                                return candidates[0] || '';
                            };
                            const pageUrl = new URL(location.href);
                            const endpoint = location.origin + '/API/CheckAvailableSigninNames' + location.search;
                            const sruRaw = pageUrl.searchParams.get('sru') || '';
                            let uaid = pageUrl.searchParams.get('uaid') || '';
                            try {
                                if (sruRaw) {
                                    const sruUrl = new URL(decodeURIComponent(sruRaw));
                                    uaid = uaid || sruUrl.searchParams.get('uaid') || '';
                                }
                            } catch (_) {}
                            const canary = findCanary();
                            if (!canary) {
                                return {ok: false, reason: 'canary_not_found', url: location.href, uaid};
                            }
                            const body = {
                                includeSuggestions: true,
                                signInName: emailFull,
                                uiflvr: 1001,
                                scid: 100118,
                                uaid,
                                hpgid: 200225
                            };
                            const started = performance.now();
                            const resp = await fetch(endpoint, {
                                method: 'POST',
                                credentials: 'include',
                                headers: {
                                    'accept': 'application/json',
                                    'content-type': 'application/json; charset=utf-8',
                                    'canary': canary,
                                    'client-request-id': uaid,
                                    'correlationid': uaid,
                                    'hpgid': '200225',
                                    'hpgact': '0',
                                    'x-outlook-register-prefetch': '1'
                                },
                                body: JSON.stringify(body)
                            });
                            const text = await resp.text();
                            let parsed = null;
                            try { parsed = JSON.parse(text); } catch (_) {}
                            return {
                                ok: resp.ok && !!parsed,
                                status: resp.status,
                                ms: Math.round((performance.now() - started) * 10) / 10,
                                endpoint,
                                uaid,
                                body,
                                responseText: text,
                                responseSummary: parsed ? {
                                    isAvailable: parsed.isAvailable,
                                    type: parsed.type,
                                    hasApiCanary: !!parsed.apiCanary,
                                    hasTelemetryContext: !!parsed.telemetryContext
                                } : null
                            };
                        }""",
                        email_full,
                    )
                    if isinstance(result, dict) and result.get("ok") and result.get("responseText"):
                        check_available_cache.update(
                            {
                                "ready": True,
                                "status": int(result.get("status") or 200),
                                "body": str(result.get("responseText") or ""),
                                "headers": {"content-type": "application/json; charset=utf-8"},
                                "prefetch": result,
                            }
                        )
                    return result
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:240]}

            takeover_log_path = None

            def write_protocol_takeover_event(record):
                nonlocal takeover_log_path
                try:
                    if takeover_log_path is None:
                        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        safe_email = self._safe_email_for_filename(f"{email}{self.email_suffix}")
                        out_dir = os.path.join(self.results_dir, "protocol_takeover")
                        os.makedirs(out_dir, exist_ok=True)
                        takeover_log_path = os.path.join(out_dir, f"{stamp}_{safe_email}.jsonl")
                        print(f"[ProtocolTakeoverV1] trace: {takeover_log_path}", flush=True)
                    payload = dict(record or {})
                    payload.setdefault("ts", datetime.now().isoformat())
                    with open(takeover_log_path, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
                except Exception:
                    pass

            def protocol_takeover_page_state():
                try:
                    return page.evaluate(
                        r"""() => {
                            const addCandidate = (arr, value) => {
                                if (typeof value !== 'string') return;
                                const v = value.trim();
                                if (v.length >= 20 && !arr.includes(v)) arr.push(v);
                            };
                            const decodeJsString = (s) => {
                                try { return JSON.parse('"' + String(s).replace(/"/g, '\\"') + '"'); }
                                catch (_) { return s; }
                            };
                            const findCanary = () => {
                                const candidates = [];
                                for (const sel of [
                                    'input[name="apiCanary"]',
                                    'input[name="canary"]',
                                    'input[name="Canary"]',
                                    'meta[name="apiCanary"]',
                                    'meta[name="canary"]'
                                ]) {
                                    const el = document.querySelector(sel);
                                    addCandidate(candidates, el?.value || el?.content || el?.getAttribute?.('content'));
                                }
                                try {
                                    const keys = Object.keys(window).slice(0, 900);
                                    for (const k of keys) {
                                        let v;
                                        try { v = window[k]; } catch (_) { continue; }
                                        if (/canary|apiCanary/i.test(k)) addCandidate(candidates, v);
                                        if (v && typeof v === 'object') {
                                            for (const kk of Object.keys(v).slice(0, 120)) {
                                                if (!/canary|apiCanary/i.test(kk)) continue;
                                                try { addCandidate(candidates, v[kk]); } catch (_) {}
                                            }
                                        }
                                    }
                                } catch (_) {}
                                try {
                                    const text = [...document.scripts].map(s => s.textContent || '').join('\n').slice(0, 4000000);
                                    const patterns = [
                                        /"apiCanary"\s*:\s*"([^"]{40,})"/i,
                                        /"canary"\s*:\s*"([^"]{40,})"/i,
                                        /apiCanary\s*[:=]\s*['"]([^'"]{40,})['"]/i,
                                        /canary\s*[:=]\s*['"]([^'"]{40,})['"]/i
                                    ];
                                    for (const re of patterns) {
                                        const m = text.match(re);
                                        if (m) addCandidate(candidates, decodeJsString(m[1]));
                                    }
                                } catch (_) {}
                                return candidates[0] || '';
                            };
                            const pageUrl = new URL(location.href);
                            const rawQuery = location.search || '';
                            const rawSruMatch = rawQuery.match(/[?&]sru=([^&]+)/i);
                            const signupReturnUrl = rawSruMatch ? rawSruMatch[1] : '';
                            const sruRaw = pageUrl.searchParams.get('sru') || '';
                            let uaid = pageUrl.searchParams.get('uaid') || '';
                            try {
                                if (sruRaw) {
                                    const sruUrl = new URL(decodeURIComponent(sruRaw));
                                    uaid = uaid || sruUrl.searchParams.get('uaid') || '';
                                }
                            } catch (_) {}
                            const brands = [];
                            try {
                                for (const b of (navigator.userAgentData && navigator.userAgentData.brands) || []) {
                                    if (b && b.brand && b.version) brands.push(`"${b.brand}";v="${b.version}"`);
                                }
                            } catch (_) {}
                            return {
                                href: location.href,
                                origin: location.origin,
                                search: location.search || '',
                                canary: findCanary(),
                                uaid,
                                signupReturnUrl,
                                userAgent: navigator.userAgent || '',
                                secChUa: brands.join(', '),
                                secChUaMobile: (navigator.userAgentData && navigator.userAgentData.mobile) ? '?1' : '?0',
                                secChUaPlatform: navigator.userAgentData?.platform ? `"${navigator.userAgentData.platform}"` : '"Windows"'
                            };
                        }"""
                    )
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:240]}

            def protocol_api_post_json(url, body, headers, label):
                started = time.time()
                post_text = json.dumps(body or {}, ensure_ascii=False, separators=(",", ":"))
                record = {
                    "event": f"{label}_request",
                    "url": url,
                    "body_len": len(post_text),
                    "body_sha256": hashlib.sha256(post_text.encode("utf-8", errors="ignore")).hexdigest(),
                }
                if self.capture_network_post_data:
                    record["body"] = self._bounded_text(post_text)
                write_protocol_takeover_event(record)
                try:
                    response = page.context.request.post(
                        url,
                        data=post_text,
                        headers=headers,
                        timeout=60000,
                    )
                    text = response.text()
                    status = int(getattr(response, "status", 0) or 0)
                    result = {"ok": 200 <= status < 300, "status": status, "text": text}
                    try:
                        result["json"] = json.loads(text or "{}")
                    except Exception:
                        result["json"] = None
                    write_protocol_takeover_event({
                        "event": f"{label}_response",
                        "url": url,
                        "status": status,
                        "elapsed_ms": int((time.time() - started) * 1000),
                        "body_len": len(text or ""),
                        "body_sha256": hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest(),
                        "body": self._bounded_text(text or "") if self.capture_network_response_body else None,
                    })
                    return result
                except Exception as exc:
                    write_protocol_takeover_event({
                        "event": f"{label}_error",
                        "url": url,
                        "elapsed_ms": int((time.time() - started) * 1000),
                        "error": repr(exc)[:500],
                    })
                    return {"ok": False, "status": 0, "text": "", "json": None, "error": repr(exc)}

            def protocol_page_fetch_json(url, body, headers, label):
                started = time.time()
                post_text = json.dumps(body or {}, ensure_ascii=False, separators=(",", ":"))
                record = {
                    "event": f"{label}_request",
                    "url": url,
                    "transport": "page_fetch",
                    "body_len": len(post_text),
                    "body_sha256": hashlib.sha256(post_text.encode("utf-8", errors="ignore")).hexdigest(),
                }
                if self.capture_network_post_data:
                    record["body"] = self._bounded_text(post_text)
                write_protocol_takeover_event(record)
                # Browser fetch cannot set forbidden headers such as Origin,
                # Referer, User-Agent or sec-ch-ua; letting the page supply
                # them keeps the post-captcha risk/verify closer to the natural
                # successful flow than Playwright's APIRequestContext.
                allowed = {
                    "accept",
                    "content-type",
                    "canary",
                    "client-request-id",
                    "correlationid",
                    "hpgact",
                    "hpgid",
                }
                fetch_headers = {
                    str(k): str(v)
                    for k, v in (headers or {}).items()
                    if str(k).lower() in allowed and v is not None
                }
                try:
                    result = page.evaluate(
                        """async ({url, body, headers}) => {
                            const response = await fetch(url, {
                                method: 'POST',
                                headers,
                                body,
                                mode: 'cors',
                                credentials: 'same-origin',
                            });
                            return {status: response.status, text: await response.text()};
                        }""",
                        {"url": url, "body": post_text, "headers": fetch_headers},
                    )
                    text = str((result or {}).get("text") or "")
                    status = int((result or {}).get("status") or 0)
                    out = {"ok": 200 <= status < 300, "status": status, "text": text}
                    try:
                        out["json"] = json.loads(text or "{}")
                    except Exception:
                        out["json"] = None
                    write_protocol_takeover_event({
                        "event": f"{label}_response",
                        "url": url,
                        "transport": "page_fetch",
                        "status": status,
                        "elapsed_ms": int((time.time() - started) * 1000),
                        "body_len": len(text or ""),
                        "body_sha256": hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest(),
                        "body": self._bounded_text(text or "") if self.capture_network_response_body else None,
                    })
                    return out
                except Exception as exc:
                    write_protocol_takeover_event({
                        "event": f"{label}_error",
                        "url": url,
                        "transport": "page_fetch",
                        "elapsed_ms": int((time.time() - started) * 1000),
                        "error": repr(exc)[:500],
                    })
                    return {"ok": False, "status": 0, "text": "", "json": None, "error": repr(exc)}

            def install_protocol_takeover_challenge_shell(challenge_url, challenge_meta=None, request_url=None):
                try:
                    return page.evaluate(
                        r"""({challengeUrl, challengeMeta, requestUrl}) => {
                            window.__protocolTakeoverMessages = window.__protocolTakeoverMessages || [];
                            window.__protocolTakeoverBootstrapPosts = [];
                            if (!window.__protocolTakeoverMessageHookInstalled) {
                                window.__protocolTakeoverMessageHookInstalled = true;
                                window.addEventListener('message', (ev) => {
                                    let preview = '';
                                    try {
                                        preview = typeof ev.data === 'string'
                                            ? ev.data
                                            : JSON.stringify(ev.data);
                                    } catch (_) {
                                        preview = String(ev.data);
                                    }
                                    const rec = {
                                        t: Date.now(),
                                        origin: ev.origin || '',
                                        preview: String(preview || '').slice(0, 1200)
                                    };
                                    window.__protocolTakeoverMessages.push(rec);
                                    if (window.__protocolTakeoverMessages.length > 80) {
                                        window.__protocolTakeoverMessages.splice(0, window.__protocolTakeoverMessages.length - 80);
                                    }
                                    // Do not remove the shell just because the
                                    // iframe posts cookie/bootstrap messages.
                                    // V1 needs the real hold button to remain
                                    // visible until the collector returns a
                                    // success result.  Earlier code treated any
                                    // message containing "HumanCaptcha", "_px3"
                                    // or "_pxde" as done, which removed the
                                    // iframe before the button mounted.
                                    if (/HumanCaptcha_Success|captcha.*success|verification.*complete|complete.*verification/i.test(rec.preview)) {
                                        window.__protocolTakeoverCaptchaDoneAt = Date.now();
                                    }
                                }, false);
                            }
                            let shell = document.getElementById('protocolTakeoverCaptchaShell');
                            if (!shell) {
                                shell = document.createElement('div');
                                shell.id = 'protocolTakeoverCaptchaShell';
                                shell.style.cssText = [
                                    'position:fixed',
                                    'inset:0',
                                    'z-index:2147483647',
                                    'background:rgba(255,255,255,0.96)',
                                    'display:flex',
                                    'align-items:center',
                                    'justify-content:center'
                                ].join(';');
                                document.body.appendChild(shell);
                            }
                            shell.innerHTML = '';
                            const iframe = document.createElement('iframe');
                            iframe.id = 'protocolTakeoverHumanCaptcha';
                            iframe.title = '验证质询';
                            iframe.setAttribute('data-testid', 'humanCaptchaIframe');
                            iframe.setAttribute('allow', 'clipboard-read; clipboard-write');
                            iframe.src = challengeUrl;
                              iframe.style.cssText = [
                                 'width:min(100vw,720px)',
                                 'height:min(100vh,620px)',
                                 'border:0',
                                 'background:white',
                                 'pointer-events:auto'
                              ].join(';');
                             shell.appendChild(iframe);
                             const meta = challengeMeta || {};
                             const appId = String(meta.appId || meta.app_id || 'PXzC5j78di');
                             const uuid = String(meta.uuid || '');
                             const vid = String(meta.vid || '');
                             const targetOrigin = 'https://iframe.hsprotect.net';
                             const posted = [];
                             let blockPosted = false;
                             const postBootstrap = (reason) => {
                                 try {
                                     if (!iframe.contentWindow) {
                                         return false;
                                     }
                                     const messages = [
                                         {type: 'setToWindow', key: '_pxAppId', value: appId},
                                         {type: 'setToWindow', key: '_pxUuid', value: uuid},
                                         {type: 'setToWindow', key: '_pxVid', value: vid}
                                     ];
                                     let didBlock = false;
                                     if (!blockPosted && uuid && vid) {
                                         messages.push({
                                             type: 'block',
                                             jsonResponse: {appId, uuid, vid},
                                             requestUrl: String(requestUrl || challengeUrl || '')
                                         });
                                         blockPosted = true;
                                         didBlock = true;
                                     }
                                     for (const msg of messages) {
                                         iframe.contentWindow.postMessage(msg, targetOrigin);
                                     }
                                     const rec = {t: Date.now(), reason, count: messages.length, block: didBlock, appId, uuid, vid};
                                     posted.push(rec);
                                     window.__protocolTakeoverBootstrapPosts.push(rec);
                                     if (window.__protocolTakeoverBootstrapPosts.length > 20) {
                                         window.__protocolTakeoverBootstrapPosts.splice(0, window.__protocolTakeoverBootstrapPosts.length - 20);
                                     }
                                     return true;
                                 } catch (e) {
                                     const rec = {t: Date.now(), reason, error: String(e && e.message || e).slice(0, 240), appId, uuid, vid};
                                     posted.push(rec);
                                     window.__protocolTakeoverBootstrapPosts.push(rec);
                                     return false;
                                 }
                             };
                             iframe.addEventListener('load', () => {
                                 postBootstrap('load');
                                 // The iframe installs its message listener from inline
                                 // script after parsing.  A few staggered posts make this
                                 // robust on slow nodes without requiring exact load timing.
                                 setTimeout(() => postBootstrap('load+250'), 250);
                                 setTimeout(() => postBootstrap('load+900'), 900);
                             });
                             setTimeout(() => postBootstrap('initial+500'), 500);
                             setTimeout(() => postBootstrap('initial+1500'), 1500);
                             return {ok: true, iframeSrc: iframe.src, bootstrap: {appId, uuid, vid, requestUrl: String(requestUrl || challengeUrl || '')}};
                        }""",
                        {
                            "challengeUrl": challenge_url,
                            "challengeMeta": challenge_meta or {},
                            "requestUrl": request_url or challenge_url,
                        },
                    )
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:240]}

            def protocol_takeover_messages():
                try:
                    return page.evaluate(
                        """() => ({
                            doneAt: window.__protocolTakeoverCaptchaDoneAt || 0,
                            messages: (window.__protocolTakeoverMessages || []).slice(-20),
                            bootstrapPosts: (window.__protocolTakeoverBootstrapPosts || []).slice(-20)
                        })"""
                    )
                except Exception:
                    return {"doneAt": 0, "messages": [], "bootstrapPosts": []}

            def read_hsprotect_solution_cookies():
                try:
                    try:
                        cookies = page.context.cookies([
                            "https://iframe.hsprotect.net",
                            "https://captcha.hsprotect.net",
                            "https://client.hsprotect.net",
                            "https://collector-pxzc5j78di.hsprotect.net",
                        ])
                    except Exception:
                        cookies = page.context.cookies()
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:200], "cookies": []}
                values = {}
                for item in cookies or []:
                    name = str(item.get("name") or "")
                    if name in {"_px3", "_pxde", "_pxvid"}:
                        values[name] = str(item.get("value") or "")
                return {
                    "ok": bool(values.get("_px3") and values.get("_pxde")),
                    "px3": values.get("_px3", ""),
                    "pxde": values.get("_pxde", ""),
                    "pxvid": values.get("_pxvid", ""),
                    "cookie_names": sorted(values.keys()),
                }

            def read_hsprotect_result0_solution():
                try:
                    capture_state = getattr(page, "_pxprobe_collector_capture", None) or {}
                except Exception:
                    capture_state = {}
                responses = list((capture_state.get("responses") if isinstance(capture_state, dict) else []) or [])
                for resp in reversed(responses):
                    try:
                        results = [str(x) for x in (resp.get("results") or [])]
                        if not any(x.startswith("oIIoIooo|0") for x in results):
                            continue
                        solution = resp.get("solution") or {}
                        px3 = str(solution.get("px3") or "")
                        pxde = str(solution.get("pxde") or "")
                        if px3 and pxde:
                            return {
                                "ok": True,
                                "px3": px3,
                                "pxde": pxde,
                                "source": "collector_result0",
                                "qi": str(resp.get("qi") or ""),
                                "seq": str(resp.get("seq") or ""),
                            }
                    except Exception:
                        continue
                return {"ok": False, "reason": "no_result0_solution"}

            def read_hsprotect_solution_candidates(cookie_solution=None, preferred_qi=""):
                """Return unique _px3/_pxde candidates seen in collector traffic.

                The non-IP failure we keep seeing is: the collector reaches W0
                result|0, but post risk/verify reloads the same HumanCaptcha.
                Live traces show this correlates with multiple concurrent qi
                families and cookie _pxde being overwritten by a later envelope.
                Try exact collector envelopes from the accepted qi first, then
                nearby bootstrap/preproof packets, and keep the cookie jar as a
                final compatibility fallback.
                """
                candidates = []
                seen = set()

                def add(sol, source, resp=None):
                    try:
                        sol = sol or {}
                        px3 = str(sol.get("px3") or "")
                        pxde = str(sol.get("pxde") or "")
                        pxvid = str(sol.get("pxvid") or "")
                        if not (px3 and pxde):
                            return
                        key = (px3, pxde, pxvid)
                        if key in seen:
                            return
                        seen.add(key)
                        item = {
                            "ok": True,
                            "px3": px3,
                            "pxde": pxde,
                            "pxvid": pxvid,
                            "source": source,
                            "px3_len": len(px3),
                            "pxde_len": len(pxde),
                        }
                        if isinstance(resp, dict):
                            item.update({
                                "qi": str(resp.get("qi") or ""),
                                "seq": str(resp.get("seq") or ""),
                                "tags": list(resp.get("tags") or []),
                                "scores": list(resp.get("scores") or []),
                                "results": list(resp.get("results") or []),
                                "status": resp.get("status"),
                            })
                        candidates.append(item)
                    except Exception:
                        pass

                # Collector envelopes are exact server responses for this
                # challenge qi; try them before the cookie jar because cookies
                # can be overwritten by a neighboring/prebootstrap iframe.
                try:
                    capture_state = getattr(page, "_pxprobe_collector_capture", None) or {}
                except Exception:
                    capture_state = {}
                responses = list((capture_state.get("responses") if isinstance(capture_state, dict) else []) or [])
                preferred_qi = str(preferred_qi or "")

                def priority(resp):
                    try:
                        tags = [str(x) for x in (resp.get("tags") or [])]
                        scores = [str(x) for x in (resp.get("scores") or [])]
                        results = [str(x) for x in (resp.get("results") or [])]
                        qi = str(resp.get("qi") or "")
                        seq = str(resp.get("seq") or "")
                        same_qi_bonus = 0 if (preferred_qi and qi == preferred_qi) else 20
                        # Prefer exact visible-challenge final envelopes, then
                        # same-qi preproof, then bootstrap/older qi fallbacks.
                        if "PX561" in tags:
                            base = 0
                        elif any(x.startswith("oIIoIooo|0") for x in results):
                            base = 5
                        elif "Y1NZWSUzXWs=" in tags:
                            base = 8
                        elif "KnpQcG8ZVUI=" in tags or "aRVTHy91Wio=" in tags:
                            base = 10
                        elif "GCQiLl1BJhk=" in tags:
                            base = 14
                        else:
                            base = 16
                        # score|0 material is usually closer to accepted state.
                        if any(x.startswith("IoIoIo|score|0") for x in scores):
                            base -= 1
                        try:
                            seq_i = int(seq)
                        except Exception:
                            seq_i = 99
                        return (same_qi_bonus + base, -seq_i)
                    except Exception:
                        return (99, 0)

                ordered = sorted(responses, key=priority)
                for resp in ordered:
                    try:
                        sol = resp.get("solution") or {}
                        add(sol, "collector", resp=resp)
                    except Exception:
                        continue

                if isinstance(cookie_solution, dict) and cookie_solution.get("ok"):
                    add(cookie_solution, "cookies")

                try:
                    limit = max(1, int(getattr(self, "signup_protocol_takeover_solution_candidate_limit", 5) or 5))
                except Exception:
                    limit = 5
                return candidates[:limit]

            def wait_hsprotect_solution_cookies(timeout_ms=None):
                timeout_ms = int(timeout_ms if timeout_ms is not None else getattr(self, "signup_protocol_takeover_cookie_timeout_ms", 9000))
                deadline = time.time() + max(500, timeout_ms) / 1000.0
                last = {}
                while time.time() < deadline:
                    last = read_hsprotect_solution_cookies()
                    if isinstance(last, dict) and last.get("ok"):
                        return last
                    page.wait_for_timeout(250)
                return last or {"ok": False, "reason": "timeout"}

            def protocol_takeover_collector_snapshot():
                try:
                    capture_state = getattr(page, "_pxprobe_collector_capture", None) or {}
                except Exception:
                    capture_state = {}
                responses = list((capture_state.get("responses") if isinstance(capture_state, dict) else []) or [])
                signals = list((capture_state.get("signals") if isinstance(capture_state, dict) else []) or [])
                pending = int((capture_state.get("collector_pending") if isinstance(capture_state, dict) else 0) or 0)
                result0 = False
                result_minus1 = False
                final_result0 = False
                w0_result0 = False
                score0 = False
                score1 = False
                latest_result = ""
                latest_qi = ""
                latest_seq = ""
                latest_tags = []
                latest_result0_qi = ""
                latest_result0_seq = ""
                for resp in responses[-12:]:
                    results = [str(x) for x in (resp.get("results") or [])]
                    scores = [str(x) for x in (resp.get("scores") or [])]
                    tags_s = [str(x) for x in (resp.get("tags") or [])]
                    if results:
                        latest_result = ",".join(results)
                        latest_qi = str(resp.get("qi") or "")
                        latest_seq = str(resp.get("seq") or "")
                        latest_tags = list(resp.get("tags") or [])
                    result0_here = any(x.startswith("oIIoIooo|0") for x in results)
                    if result0_here:
                        result0 = True
                        latest_result0_qi = str(resp.get("qi") or latest_result0_qi or "")
                        latest_result0_seq = str(resp.get("seq") or latest_result0_seq or "")
                        if "PX561" in tags_s:
                            final_result0 = True
                        if "W0cqQR4rLnA=" in tags_s:
                            w0_result0 = True
                    if any(x.startswith("oIIoIooo|-1") for x in results):
                        result_minus1 = True
                    if any(x.startswith("IoIoIo|score|0") for x in scores):
                        score0 = True
                    if any(x.startswith("IoIoIo|score|1") for x in scores):
                        score1 = True
                human_success = any(sig.get("label") == "HumanCaptcha_Success" for sig in signals[-30:])
                human_failure = any(sig.get("label") == "HumanCaptcha_Failure" for sig in signals[-30:])
                loaded = any(sig.get("label") == "HumanCaptcha_Loaded" for sig in signals[-30:])
                captcha_js = any(sig.get("label") == "captcha_js" for sig in signals[-30:])
                return {
                    "pending": pending,
                    "responses": len(responses),
                    "signals": len(signals),
                    "result0": result0,
                    "result_minus1": result_minus1,
                    "final_result0": final_result0,
                    "w0_result0": w0_result0,
                    "latest_result0_qi": latest_result0_qi,
                    "latest_result0_seq": latest_result0_seq,
                    "score0": score0,
                    "score1": score1,
                    "human_success": human_success,
                    "human_failure": human_failure,
                    "loaded": loaded,
                    "captcha_js": captcha_js,
                    "latest_result": latest_result,
                    "latest_qi": latest_qi,
                    "latest_seq": latest_seq,
                    "latest_tags": latest_tags,
                    "recent_signals": [
                        {
                            "label": sig.get("label"),
                            "phase": sig.get("phase"),
                            "status": sig.get("status"),
                        }
                        for sig in signals[-8:]
                    ],
                    "recent_responses": [
                        {
                            "qi": resp.get("qi"),
                            "seq": resp.get("seq"),
                            "tags": resp.get("tags"),
                            "scores": resp.get("scores"),
                            "results": resp.get("results"),
                            "status": resp.get("status"),
                        }
                        for resp in responses[-6:]
                    ],
                }

            def wait_hsprotect_protocol_success(handler_ok=False, timeout_ms=None, prefer_postcaptcha_ready=False):
                timeout_ms = int(timeout_ms if timeout_ms is not None else max(
                    1500,
                    int(getattr(self, "signup_protocol_takeover_cookie_timeout_ms", 9000) or 9000),
                ))
                deadline = time.time() + max(500, timeout_ms) / 1000.0
                last = protocol_takeover_collector_snapshot()
                fallback_result0 = None
                while time.time() < deadline:
                    last = protocol_takeover_collector_snapshot()
                    if prefer_postcaptcha_ready:
                        # In the stable semi-protocol traces the decisive host
                        # handoff is not merely "some collector result|0".
                        # The natural accepted path is usually:
                        #   PX561/final neutral -> W0 result|0 -> risk/verify.
                        # V1 previously returned as soon as a final PX561
                        # result|0 appeared, which produced valid-looking
                        # cookies but risk/verify re-issued the same
                        # HumanCaptcha.  Prefer a W0 result|0 or the iframe's
                        # HumanCaptcha_Success bridge; keep final result|0 only
                        # as a bounded fallback for diagnostics/older 1s
                        # shapes.
                        if last.get("w0_result0") or last.get("human_success"):
                            last["ok"] = True
                            last["reason"] = "w0_result0" if last.get("w0_result0") else "human_success"
                            return last
                        if last.get("result0") or handler_ok:
                            fallback_result0 = dict(last)
                        if last.get("result_minus1") and not last.get("pending") and not fallback_result0:
                            page.wait_for_timeout(350)
                            tail = protocol_takeover_collector_snapshot()
                            if tail.get("w0_result0") or tail.get("human_success"):
                                tail["ok"] = True
                                tail["reason"] = "late_w0_or_success_after_minus1"
                                return tail
                            tail["ok"] = False
                            tail["reason"] = "collector_minus1"
                            return tail
                        page.wait_for_timeout(200)
                        continue
                    if handler_ok or last.get("result0") or last.get("human_success"):
                        last["ok"] = True
                        last["reason"] = (
                            "handler_ok" if handler_ok else
                            "collector_result0" if last.get("result0") else
                            "human_success"
                        )
                        return last
                    # result|-1 is decisive for the current proof attempt; keep
                    # waiting only briefly for trailing success telemetry.
                    if last.get("result_minus1") and not last.get("pending"):
                        page.wait_for_timeout(350)
                        tail = protocol_takeover_collector_snapshot()
                        if tail.get("result0") or tail.get("human_success"):
                            tail["ok"] = True
                            tail["reason"] = "late_success_after_minus1"
                            return tail
                        tail["ok"] = False
                        tail["reason"] = "collector_minus1"
                        return tail
                    page.wait_for_timeout(200)
                if prefer_postcaptcha_ready and fallback_result0:
                    fallback_result0["ok"] = True
                    fallback_result0["reason"] = "final_result0_fallback"
                    fallback_result0["fallback_wait_ms"] = timeout_ms
                    return fallback_result0
                last["ok"] = bool(handler_ok or last.get("result0") or last.get("human_success"))
                last.setdefault("reason", "timeout")
                return last

            def trigger_protocol_takeover_success_signals(qi="", reason="protocol_takeover_result0"):
                """Best-effort bridge from hsprotect result|0 back into the iframe/host callbacks.

                V1 drives risk/verify manually, but the real challenge iframe can
                still need its local success callbacks to run so that cookies,
                close/status messages and browser telemetry settle like the
                natural semi-protocol path.  This is intentionally best-effort:
                failure to call a callback is logged but does not block the
                verified collector state.
                """
                token = f"protocol-takeover-{int(time.time() * 1000)}"
                script = r"""({token, qi, reason}) => {
                    const out = [];
                    const rec = (kind, data) => {
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
                            for (const args of variants) {
                                try {
                                    window._pxOnCaptchaSuccess.apply(window, args);
                                    rec("callback", {name: "_pxOnCaptchaSuccess", argc: args.length});
                                    break;
                                } catch (e) {
                                    rec("callback_error", {name: "_pxOnCaptchaSuccess", argc: args.length, error: String(e && e.message || e).slice(0, 180)});
                                }
                            }
                        }
                    } catch (e) {
                        rec("callback_outer_error", {error: String(e && e.message || e).slice(0, 180)});
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
                                window.dispatchEvent(new CustomEvent(name, {detail}));
                                document.dispatchEvent(new CustomEvent(name, {detail}));
                                rec("event", {name});
                            } catch (e) {
                                rec("event_error", {name, error: String(e && e.message || e).slice(0, 120)});
                            }
                        }
                    } catch (_) {}
                    try {
                        const messages = [
                            detail,
                            {type: "captcha_success", detail},
                            {type: "pxCaptchaSuccess", payload: detail},
                            {event: "captcha_success", status: 0, captchaToken: token, token, appID: "PXzC5j78di"},
                            {action: "captcha_close", status: 0, captchaToken: token, token, appID: "PXzC5j78di"}
                        ];
                        const targets = [];
                        try { if (window.parent && window.parent !== window) targets.push(["parent", window.parent]); } catch (_) {}
                        try { if (window.top && window.top !== window && window.top !== window.parent) targets.push(["top", window.top]); } catch (_) {}
                        for (const [label, target] of targets) {
                            for (const msg of messages) {
                                try {
                                    target.postMessage(msg, "*");
                                    rec("postMessage", {target: label});
                                } catch (e) {
                                    rec("postMessage_error", {target: label, error: String(e && e.message || e).slice(0, 120)});
                                }
                            }
                        }
                    } catch (_) {}
                    return {href: location.href, out};
                }"""
                results = []
                try:
                    for idx, frame in enumerate(page.frames):
                        try:
                            frame_url = getattr(frame, "url", "") or ""
                            if idx != 0 and "hsprotect.net" not in frame_url and frame_url != "about:blank":
                                continue
                            res = frame.evaluate(script, {"token": token, "qi": str(qi or ""), "reason": reason})
                            results.append({"idx": idx, "url": frame_url[:180], "result": res})
                        except Exception as exc:
                            results.append({
                                "idx": idx,
                                "url": (getattr(frame, "url", "") or "")[:180],
                                "error": repr(exc)[:240],
                            })
                    write_protocol_takeover_event({
                        "event": "success_signal_bridge",
                        "qi": qi,
                        "reason": reason,
                        "results": results,
                    })
                    return {"ok": True, "results": results}
                except Exception as exc:
                    out = {"ok": False, "error": repr(exc)[:300], "results": results}
                    write_protocol_takeover_event({"event": "success_signal_bridge_error", **out})
                    return out

            def classify_protocol_create_response(status, body):
                try:
                    if int(status or 0) != 200:
                        return {"ok": False, "reason": f"http_{status}"}
                    parsed = json.loads(body or "{}")
                    if not isinstance(parsed, dict):
                        return {"ok": False, "reason": type(parsed).__name__}
                    err = parsed.get("error")
                    if isinstance(err, dict):
                        return {"ok": False, "reason": "error", "error_code": str(err.get("code") or "")}
                    markers = [
                        bool(parsed.get("signinName")),
                        bool(parsed.get("slt")),
                        bool(parsed.get("redirectUrl")),
                        bool(parsed.get("encPuid")),
                    ]
                    if sum(1 for x in markers if x) >= 2 and parsed.get("signinName") and parsed.get("slt"):
                        return {"ok": True, "reason": "success_body", "signinName": parsed.get("signinName")}
                    return {"ok": False, "reason": "unknown_body_shape", "keys": sorted(parsed.keys())}
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:200]}

            def mark_protocol_create_success(summary):
                try:
                    with self.signup_network_lock:
                        state = self.signup_network_state.setdefault(id(page), {
                            "create_requests": 0,
                            "create_responses": [],
                            "create_success": False,
                            "create_done": False,
                            "create_failures": [],
                            "create_last": {},
                            "risk_verify_responses": [],
                            "riskblock": False,
                        })
                        state["create_requests"] = int(state.get("create_requests") or 0) + 1
                        state.setdefault("create_responses", []).append(200)
                        state["create_success"] = True
                        state["create_done"] = True
                        state["create_last"] = dict(summary or {})
                except Exception:
                    pass

            def run_protocol_takeover_v1():
                email_full = f"{email}{self.email_suffix}"
                write_protocol_takeover_event({
                    "event": "start",
                    "mode": signup_mode,
                    "email": email_full,
                    "firstName": firstname,
                    "lastName": lastname,
                    "birth": {"year": year, "month": month, "day": day},
                })
                if not protocol_takeover_thin:
                    accept_initial_consent_gate(timeout_ms=10000)
                state = protocol_takeover_page_state()
                if protocol_takeover_thin and not (state.get("canary") and state.get("uaid")):
                    write_protocol_takeover_event({
                        "event": "thin_state_missing_before_gate_retry",
                        "has_canary": bool(state.get("canary")),
                        "uaid": state.get("uaid"),
                        "href": state.get("href"),
                    })
                    accept_initial_consent_gate(timeout_ms=3500)
                    state = protocol_takeover_page_state()
                write_protocol_takeover_event({
                    "event": "page_state",
                    "href": state.get("href"),
                    "has_canary": bool(state.get("canary")),
                    "uaid": state.get("uaid"),
                    "signupReturnUrl_len": len(str(state.get("signupReturnUrl") or "")),
                })
                canary = str(state.get("canary") or "")
                uaid = str(state.get("uaid") or "")
                if not canary or not uaid:
                    print(f"[ProtocolTakeoverV1] missing page state canary={bool(canary)} uaid={uaid!r}", flush=True)
                    return False

                base_headers = {
                    "accept": "application/json",
                    "content-type": "application/json; charset=utf-8",
                    "origin": "https://signup.live.com",
                    "referer": "https://signup.live.com/",
                    "user-agent": state.get("userAgent") or "",
                    "canary": canary,
                    "client-request-id": uaid,
                    "correlationid": uaid,
                    "hpgact": "0",
                    "hpgid": "200225",
                }
                if state.get("secChUa"):
                    base_headers["sec-ch-ua"] = state.get("secChUa")
                if state.get("secChUaMobile"):
                    base_headers["sec-ch-ua-mobile"] = state.get("secChUaMobile")
                if state.get("secChUaPlatform"):
                    base_headers["sec-ch-ua-platform"] = state.get("secChUaPlatform")

                risk_init_url = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/api/v1.0/risk/initialize"
                risk_init = None
                risk_init_json = None
                risk_init_source = "api"
                if bool(getattr(self, "signup_protocol_takeover_use_observed_risk_init", True)):
                    try:
                        wait_ms = max(
                            0,
                            int(getattr(self, "signup_protocol_takeover_observed_risk_init_wait_ms", 2500) or 0),
                        )
                        if risk_initialize_cache and not risk_initialize_cache.get("observed") and wait_ms:
                            observed_deadline = time.time() + wait_ms / 1000.0
                            while time.time() < observed_deadline and not risk_initialize_cache.get("observed"):
                                page.wait_for_timeout(100)
                        observed_body = ""
                        observed_status = 0
                        if risk_initialize_cache and risk_initialize_cache.get("observed"):
                            observed_body = str(risk_initialize_cache.get("body") or "")
                            observed_status = int(risk_initialize_cache.get("status") or 0)
                        if observed_body and 200 <= observed_status < 300:
                            parsed_observed = json.loads(observed_body or "{}")
                            observed_token = str((parsed_observed or {}).get("continuationToken") or "")
                            if observed_token:
                                risk_init = {
                                    "ok": True,
                                    "status": observed_status,
                                    "text": observed_body,
                                    "json": parsed_observed,
                                    "observed": True,
                                }
                                risk_init_json = parsed_observed
                                risk_init_source = "observed_page"
                    except Exception as exc:
                        write_protocol_takeover_event({
                            "event": "risk_initialize_observed_parse_error",
                            "error": repr(exc)[:240],
                        })
                # Natural Fluent signup fires risk/initialize very early with
                # the page canary, while CheckAvailable returns the newer
                # apiCanary used by the later verify/create calls.  Prefer the
                # already-observed page risk/initialize response so thin V2 does
                # not create a second invisible risk session before loading the
                # HumanCaptcha shell.  Fall back to the explicit protocol call
                # only when the page did not expose a usable token.
                if risk_init_json is None:
                    risk_init_transport = str(
                        getattr(self, "signup_protocol_takeover_risk_init_transport", "auto") or "auto"
                    ).strip().lower()
                    if risk_init_transport == "auto":
                        # Thin V2 intentionally takes over before the visible
                        # form can fire every natural request.  If no observed
                        # risk/initialize is available, prefer browser fetch so
                        # CORS/page headers/cookie behavior match the later
                        # risk/verify calls; fall back to APIRequestContext only
                        # when browser fetch cannot produce a token.
                        risk_init_transport = "page_fetch" if protocol_takeover_thin else "api"
                    if risk_init_transport in {"page_fetch", "page", "fetch", "browser"}:
                        risk_init = protocol_page_fetch_json(
                            risk_init_url,
                            {"continuationToken": ""},
                            base_headers,
                            "risk_initialize",
                        )
                        risk_init_json = risk_init.get("json") if isinstance(risk_init, dict) else None
                        risk_init_source = "page_fetch"
                        if not (isinstance(risk_init_json, dict) and risk_init_json.get("continuationToken")):
                            write_protocol_takeover_event({
                                "event": "risk_initialize_page_fetch_fallback_to_api",
                                "status": risk_init.get("status") if isinstance(risk_init, dict) else None,
                            })
                            risk_init = protocol_api_post_json(risk_init_url, {"continuationToken": ""}, base_headers, "risk_initialize_api_fallback")
                            risk_init_json = risk_init.get("json") if isinstance(risk_init, dict) else None
                            risk_init_source = "api_fallback"
                    else:
                        risk_init = protocol_api_post_json(risk_init_url, {"continuationToken": ""}, base_headers, "risk_initialize")
                        risk_init_json = risk_init.get("json") if isinstance(risk_init, dict) else None
                        risk_init_source = "api"
                write_protocol_takeover_event({
                    "event": "risk_initialize_source",
                    "source": risk_init_source,
                    "status": risk_init.get("status") if isinstance(risk_init, dict) else None,
                    "token_len": len(str((risk_init_json or {}).get("continuationToken") or "")) if isinstance(risk_init_json, dict) else 0,
                    "observed_ready": bool(risk_initialize_cache and risk_initialize_cache.get("observed")),
                })
                init_token = str((risk_init_json or {}).get("continuationToken") or "")
                if not init_token:
                    print(f"[ProtocolTakeoverV1] risk/initialize failed status={risk_init.get('status')} json={risk_init_json}", flush=True)
                    return False

                check_url = f"{state.get('origin') or 'https://signup.live.com'}/API/CheckAvailableSigninNames{state.get('search') or ''}"
                check_body = {
                    "includeSuggestions": True,
                    "signInName": email_full,
                    "uiflvr": 1001,
                    "scid": 100118,
                    "uaid": uaid,
                    "hpgid": 200225,
                }
                check_headers = dict(base_headers)
                check_headers["referer"] = state.get("href") or "https://signup.live.com/"
                check = protocol_api_post_json(check_url, check_body, check_headers, "check_available")
                check_json = check.get("json") if isinstance(check, dict) else None
                if not (isinstance(check_json, dict) and check_json.get("isAvailable")):
                    print(f"[ProtocolTakeoverV1] CheckAvailable failed status={check.get('status')} json={check_json}", flush=True)
                    return False
                api_canary = str(check_json.get("apiCanary") or canary)
                if api_canary:
                    base_headers["canary"] = api_canary

                try:
                    mm = f"{max(1, min(12, int(month))):02d}"
                    dd = f"{max(1, min(31, int(day))):02d}"
                except Exception:
                    mm, dd = "01", "01"
                birthdate = f"{mm}:{dd}:{year}"
                country_code = str(fill_profile.get("country_code") or fill_profile.get("country") or os.environ.get("OUTLOOK_SIGNUP_COUNTRY_CODE", "LK") or "LK")
                pre_verify_body = {
                    "continuationToken": init_token,
                    "riskProviderMetadata": [
                        {"riskProvider": "Human", "px3": "", "pxde": "", "pxvid": ""}
                    ],
                    "msaRiskVerifySignature": {
                        "memberName": email_full,
                        "siteId": "00000000487A244A",
                        "uiFlavor": "Web",
                        "appId": "00000000487A244A",
                        "birthdate": birthdate,
                        "firstName": firstname,
                        "lastName": lastname,
                        "countryCode": country_code,
                        "verificationCode": "",
                        "deviceDetails": {"isRdm": False},
                        "action": "SignUp",
                    },
                }
                def create_protocol_account(continue_token, source=""):
                    continue_token = str(continue_token or "")
                    if not continue_token:
                        print(f"[ProtocolTakeoverV1] CreateAccount skipped missing continuation source={source}", flush=True)
                        return False
                    create_url = f"{state.get('origin') or 'https://signup.live.com'}/API/CreateAccount{state.get('search') or ''}"
                    create_headers = dict(base_headers)
                    create_headers["referer"] = state.get("href") or "https://signup.live.com/"
                    create_body = {
                        "BirthDate": birthdate,
                        "CheckAvailStateMap": [f"{email_full}:false"],
                        "Country": country_code,
                        "EvictionWarningShown": [],
                        "FirstName": firstname,
                        "IsRDM": False,
                        "IsOptOutEmailDefault": False,
                        "IsOptOutEmailShown": 1,
                        "IsOptOutEmail": False,
                        "IsUserConsentedToChinaPIPL": False,
                        "LastName": lastname,
                        "LW": 1,
                        "MemberName": email_full,
                        "RequestTimeStamp": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
                        "ReturnUrl": "",
                        "SignupReturnUrl": state.get("signupReturnUrl") or "",
                        "SuggestedAccountType": "OUTLOOK",
                        "SiteId": "",
                        "VerificationCodeSlt": "",
                        "PrivateAccessToken": "",
                        "WReply": "",
                        "MemberNameChangeCount": 1,
                        "MemberNameAvailableCount": 1,
                        "MemberNameUnavailableCount": 0,
                        "Password": password,
                        "ContinuationToken": continue_token,
                        "uiflvr": 1001,
                        "scid": 100118,
                        "uaid": uaid,
                        "hpgid": 200225,
                    }
                    create = protocol_api_post_json(create_url, create_body, create_headers, "create_account")
                    create_summary = classify_protocol_create_response(create.get("status"), create.get("text"))
                    write_protocol_takeover_event({
                        "event": "create_account_summary",
                        "source": source,
                        "summary": create_summary,
                    })
                    if create_summary.get("ok"):
                        mark_protocol_create_success(create_summary)
                        print(
                            f"[ProtocolTakeoverV1] CreateAccount strict success "
                            f"source={source} signin={create_summary.get('signinName')}",
                            flush=True,
                        )
                        return True
                    print(f"[ProtocolTakeoverV1] CreateAccount failed source={source} summary={create_summary}", flush=True)
                    return False

                risk_verify_url = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/api/v1.0/risk/verify"
                if protocol_takeover_thin:
                    try:
                        min_total_ms = max(
                            0,
                            int(getattr(self, "signup_protocol_takeover_preverify_min_total_ms", 0) or 0),
                        )
                    except Exception:
                        min_total_ms = 0
                    if min_total_ms:
                        elapsed_total_ms = int((time.time() - fill_phase_t0) * 1000)
                        wait_ms = max(0, min_total_ms - elapsed_total_ms)
                        if wait_ms:
                            write_protocol_takeover_event({
                                "event": "thin_preverify_pacing_wait",
                                "min_total_ms": min_total_ms,
                                "elapsed_total_ms": elapsed_total_ms,
                                "wait_ms": wait_ms,
                            })
                            page.wait_for_timeout(wait_ms)
                # Successful natural/semi-protocol samples send the first
                # risk/verify from the page's own fetch stack.  Using
                # APIRequestContext here is visibly different (not tied to the
                # page fetch pipeline / CORS header generation) and recent V1
                # batches were dying at this exact pre-captcha 403 branch.  Keep
                # an escape hatch for A/B tests, but default V1 to page_fetch.
                preverify_transport = str(
                    getattr(self, "signup_protocol_takeover_preverify_transport", "page_fetch")
                    or "page_fetch"
                ).strip().lower()
                if preverify_transport in {"api", "api_request", "context", "request"}:
                    pre_verify = protocol_api_post_json(risk_verify_url, pre_verify_body, base_headers, "risk_verify_pre")
                else:
                    pre_verify = protocol_page_fetch_json(risk_verify_url, pre_verify_body, base_headers, "risk_verify_pre")
                pre_json = pre_verify.get("json") if isinstance(pre_verify, dict) else None
                if int(pre_verify.get("status") or 0) in {401, 403, 429}:
                    print(
                        "[ProtocolTakeoverV1] pre-captcha risk/verify riskblock "
                        f"transport={preverify_transport} status={pre_verify.get('status')}",
                        flush=True,
                    )
                    return False
                challenge = ((pre_json or {}).get("challengeDetails") or {}) if isinstance(pre_json, dict) else {}
                challenge_meta = challenge.get("challengeMetadata") or {}
                challenge_url = str(challenge_meta.get("challengeUrl") or "")
                challenge_token = str((pre_json or {}).get("continuationToken") or "")
                if not (challenge_url and challenge_token):
                    if isinstance(pre_json, dict) and pre_json.get("state") == "continue" and challenge_token:
                        print("[ProtocolTakeoverV1] pre-captcha risk/verify returned continue; skipping HumanCaptcha", flush=True)
                        write_protocol_takeover_event({
                            "event": "risk_verify_pre_continue_without_challenge",
                            "continue_len": len(challenge_token),
                        })
                        return create_protocol_account(challenge_token, "pre_verify_continue")
                    print(f"[ProtocolTakeoverV1] no HumanCaptcha challenge json={pre_json}", flush=True)
                    return False
                # The pre-challenge sensor iframe uses the bare challengeUrl.
                # The visible hold challenge is loaded by the signup host with
                # ch_ctx=1.  Loading the bare URL in our V1 shell only produces
                # _px3/_pxde cookie churn and never mounts captcha.js/button.
                shell_challenge_url = challenge_url
                if "ch_ctx=1" not in shell_challenge_url:
                    shell_challenge_url += ("&" if "?" in shell_challenge_url else "?") + "ch_ctx=1"
                shell_result = install_protocol_takeover_challenge_shell(
                    shell_challenge_url,
                    challenge_meta=challenge_meta,
                    request_url=state.get("href") or state.get("origin") or "https://signup.live.com/",
                )
                print(f"[ProtocolTakeoverV1] challenge shell result={shell_result}", flush=True)
                write_protocol_takeover_event({
                    "event": "challenge_shell",
                    "result": shell_result,
                    "challengeUrl": challenge_url,
                    "shellChallengeUrl": shell_challenge_url,
                    "challengeType": challenge.get("challengeType"),
                    "metadata": {k: challenge_meta.get(k) for k in ("appId", "uuid", "vid")},
                })

                captcha_ok = False
                captcha_error = ""
                try:
                    try:
                        setattr(self, "_protocol_takeover_accept_result0", True)
                    except Exception:
                        pass
                    captcha_ok = bool(self.handle_captcha(page))
                except Exception as exc:
                    captcha_error = repr(exc)
                finally:
                    try:
                        setattr(self, "_protocol_takeover_accept_result0", False)
                    except Exception:
                        pass
                messages = protocol_takeover_messages()
                write_protocol_takeover_event({
                    "event": "captcha_handler_done",
                    "ok": captcha_ok,
                    "error": captcha_error[:500],
                    "messages": messages,
                })

                protocol_success = wait_hsprotect_protocol_success(
                    handler_ok=captcha_ok,
                    prefer_postcaptcha_ready=True,
                )
                write_protocol_takeover_event({
                    "event": "captcha_protocol_success_wait",
                    "result": protocol_success,
                })
                if not protocol_success.get("ok"):
                    print(
                        "[ProtocolTakeoverV1] captcha protocol success not observed "
                        f"after handler ok={captcha_ok} result={protocol_success}",
                        flush=True,
                    )
                    return False
                try:
                    bridge_qi = str(protocol_success.get("latest_result0_qi") or protocol_success.get("latest_qi") or "")
                    bridge_reason = str(protocol_success.get("reason") or "protocol_takeover_result0")
                    bridge = trigger_protocol_takeover_success_signals(bridge_qi, bridge_reason)
                    # Give iframe cookie/status callbacks a short deterministic
                    # settle window before reading the final solution material.
                    page.wait_for_timeout(350)
                    post_bridge = protocol_takeover_collector_snapshot()
                    write_protocol_takeover_event({
                        "event": "post_success_signal_snapshot",
                        "bridge": bridge,
                        "snapshot": post_bridge,
                    })
                except Exception as exc:
                    write_protocol_takeover_event({
                        "event": "success_signal_bridge_exception",
                        "error": repr(exc)[:300],
                    })

                cookie_solution = wait_hsprotect_solution_cookies()
                if not cookie_solution.get("ok"):
                    print(f"[ProtocolTakeoverV1] captcha solution cookies missing after handler ok={captcha_ok} solution={cookie_solution}", flush=True)
                    return False
                collector_solution = read_hsprotect_result0_solution()
                solution = dict(cookie_solution)
                if collector_solution.get("ok") and not (
                    protocol_success.get("w0_result0") or protocol_success.get("human_success")
                ):
                    # Tail/W0 packets can overwrite _pxde after the accepted
                    # final proof.  risk/verify matches the result|0 proof more
                    # reliably when we use the exact _px3/_pxde returned on the
                    # collector result|0 response, while keeping _pxvid from the
                    # browser cookie jar.
                    solution["px3"] = collector_solution.get("px3") or solution.get("px3") or ""
                    solution["pxde"] = collector_solution.get("pxde") or solution.get("pxde") or ""
                    solution["source"] = collector_solution.get("source")
                    solution["collector_qi"] = collector_solution.get("qi")
                    solution["collector_seq"] = collector_solution.get("seq")
                if not solution.get("pxvid"):
                    solution["pxvid"] = str(challenge_meta.get("vid") or "")
                settle_ms = max(0, int(getattr(self, "signup_protocol_takeover_post_success_settle_ms", 650) or 0))
                if settle_ms:
                    page.wait_for_timeout(settle_ms)

                preferred_qi = str(protocol_success.get("latest_result0_qi") or protocol_success.get("latest_qi") or "")
                solution_candidates = read_hsprotect_solution_candidates(solution, preferred_qi=preferred_qi)
                if not solution_candidates:
                    solution_candidates = [solution]
                # Preserve the browser cookie _pxvid unless a candidate already
                # carries one.  The collector response itself only contains px3/pxde.
                for cand in solution_candidates:
                    if not cand.get("pxvid"):
                        cand["pxvid"] = str(solution.get("pxvid") or challenge_meta.get("vid") or "")
                try:
                    allow_solution_fallbacks = bool(getattr(self, "signup_protocol_takeover_solution_fallbacks", True))
                except Exception:
                    allow_solution_fallbacks = True

                write_protocol_takeover_event({
                    "event": "solution_candidates",
                    "preferred_qi": preferred_qi,
                    "allow_fallbacks": allow_solution_fallbacks,
                    "count": len(solution_candidates),
                    "candidates": [
                        {
                            "idx": idx,
                            "source": cand.get("source"),
                            "qi": cand.get("qi"),
                            "seq": cand.get("seq"),
                            "tags": cand.get("tags"),
                            "px3_len": len(cand.get("px3") or ""),
                            "pxde_len": len(cand.get("pxde") or ""),
                            "pxvid_len": len(cand.get("pxvid") or ""),
                        }
                        for idx, cand in enumerate(solution_candidates, start=1)
                    ],
                })

                post_verify = {"status": 0, "json": None}
                post_json = None
                continue_token = ""
                accepted_solution_idx = 0
                last_post_summary = {}

                for idx, candidate in enumerate(solution_candidates, start=1):
                    if idx > 1 and not allow_solution_fallbacks:
                        break
                    post_verify_body = {
                        "continuationToken": challenge_token,
                        "challengeSolution": {
                            "challengeType": "HumanCaptcha",
                            "px3": candidate.get("px3") or "",
                            "pxde": candidate.get("pxde") or "",
                            "pxvid": candidate.get("pxvid") or "",
                        },
                        "riskProviderMetadata": [
                            {
                                "riskProvider": "Human",
                                "px3": candidate.get("px3") or "",
                                "pxde": candidate.get("pxde") or "",
                                "pxvid": candidate.get("pxvid") or "",
                            }
                        ],
                    }
                    label = "risk_verify_post" if idx == 1 else f"risk_verify_post_solution_fallback_{idx}"
                    print(
                        "[ProtocolTakeoverV1] solution candidate "
                        f"idx={idx}/{len(solution_candidates)} source={candidate.get('source') or 'unknown'} "
                        f"qi={candidate.get('qi') or '-'} seq={candidate.get('seq') or '-'} "
                        f"px3_len={len(candidate.get('px3') or '')} pxde_len={len(candidate.get('pxde') or '')} "
                        f"pxvid={str(candidate.get('pxvid') or '')[:24]}",
                        flush=True,
                    )
                    write_protocol_takeover_event({
                        "event": "solution_candidate_attempt",
                        "idx": idx,
                        "source": candidate.get("source") or "unknown",
                        "qi": candidate.get("qi"),
                        "seq": candidate.get("seq"),
                        "tags": candidate.get("tags"),
                        "px3_len": len(candidate.get("px3") or ""),
                        "pxde_len": len(candidate.get("pxde") or ""),
                        "pxvid_len": len(candidate.get("pxvid") or ""),
                    })
                    post_verify = protocol_page_fetch_json(risk_verify_url, post_verify_body, base_headers, label)
                    post_json = post_verify.get("json") if isinstance(post_verify, dict) else None
                    continue_token = str((post_json or {}).get("continuationToken") or "")
                    last_post_summary = {
                        "idx": idx,
                        "status": post_verify.get("status") if isinstance(post_verify, dict) else None,
                        "state": (post_json or {}).get("state") if isinstance(post_json, dict) else "",
                        "continue_len": len(continue_token),
                        "challengeType": (((post_json or {}).get("challengeDetails") or {}).get("challengeType") if isinstance(post_json, dict) else ""),
                    }
                    write_protocol_takeover_event({"event": "solution_candidate_response", **last_post_summary})
                    if isinstance(post_json, dict) and post_json.get("state") == "continue" and continue_token:
                        accepted_solution_idx = idx
                        solution = dict(candidate)
                        print(
                            "[ProtocolTakeoverV1] post-captcha risk/verify accepted "
                            f"solution_idx={idx} source={candidate.get('source') or 'unknown'}",
                            flush=True,
                        )
                        break

                if not (isinstance(post_json, dict) and post_json.get("state") == "continue" and continue_token):
                    print(
                        f"[ProtocolTakeoverV1] post-captcha risk/verify did not continue "
                        f"status={post_verify.get('status')} summary={last_post_summary} json={post_json}",
                        flush=True,
                    )
                    return False

                write_protocol_takeover_event({
                    "event": "solution_accepted",
                    "idx": accepted_solution_idx,
                    "source": solution.get("source") or "unknown",
                    "qi": solution.get("qi"),
                    "seq": solution.get("seq"),
                    "px3_len": len(solution.get("px3") or ""),
                    "pxde_len": len(solution.get("pxde") or ""),
                    "pxvid_len": len(solution.get("pxvid") or ""),
                })
                return create_protocol_account(continue_token, "post_verify_continue")

            if protocol_takeover:
                mark_fill_phase("protocol_takeover_v1_start")
                if run_protocol_takeover_v1():
                    mark_fill_phase("protocol_takeover_v1_done", "success=True")
                    return finalize_registration_success()
                mark_fill_phase("protocol_takeover_v1_done", "success=False")
                self.save_diagnostic(page, "protocol_takeover_v1_failed", email)
                return False

            def set_email_suffix_trusted(suffix):
                suffix = str(suffix or "").strip()
                if not suffix:
                    return {"ok": False, "reason": "empty"}
                try:
                    if page.get_by_text(suffix, exact=True).count() > 0:
                        return {"ok": True, "via": "already_visible"}
                except Exception:
                    pass
                for current in ["@outlook.com", "@outlook.jp", "@hotmail.com"]:
                    if current == suffix:
                        continue
                    try:
                        loc = page.get_by_text(current, exact=True)
                        if loc.count() <= 0:
                            continue
                        first = loc.first() if callable(getattr(loc, "first", None)) else loc.first
                        first.click(timeout=3500)
                        page.wait_for_timeout(350)
                        opt = page.get_by_text(suffix, exact=True)
                        if opt.count() > 0:
                            opt_first = opt.first() if callable(getattr(opt, "first", None)) else opt.first
                            opt_first.click(timeout=3500)
                            page.wait_for_timeout(250)
                            return {"ok": True, "via": "trusted_text", "from": current, "to": suffix}
                    except Exception:
                        continue
                return set_email_suffix(suffix)

            def type_signup_email_trusted(value):
                value = str(value or "")
                selectors = [
                    # Current Fluent signup builds have rotated names/data-testid
                    # a few times. Keep the list broad but still restricted to
                    # visible non-password input controls so score probes can
                    # avoid the JS value-set fallback.
                    'input[data-testid*="username" i]',
                    'input[data-testid*="member" i]',
                    'input[data-testid*="email" i]',
                    'input[data-testid*="signin" i]',
                    'input[autocomplete*="username" i]',
                    'input[autocomplete*="email" i]',
                    '[name*="MemberName" i]',
                    '[name*="member" i]',
                    '[name*="username" i]',
                    '[name*="login" i]',
                    '[name*="email" i]',
                    '[id*="MemberName" i]',
                    '[id*="member" i]',
                    '[id*="username" i]',
                    '[id*="email" i]',
                    'input[type="email"]',
                    'input[aria-label*="メール"]',
                    'input[placeholder*="メール"]',
                    'input[aria-label*="邮箱"]',
                    'input[aria-label*="电子"]',
                    'input[aria-label*="邮件"]',
                    'input[placeholder*="邮箱"]',
                    'input[placeholder*="电子"]',
                    'input[placeholder*="邮件"]',
                    'input[aria-label*="mail" i]',
                    'input[aria-label*="email" i]',
                    'input[placeholder*="mail" i]',
                    'input[placeholder*="email" i]',
                    'input[type="text"]',
                    'input:not([type])',
                ]
                for selector in selectors:
                    try:
                        loc = page.locator(selector)
                        if loc.count() <= 0:
                            continue
                        first = loc.first() if callable(getattr(loc, "first", None)) else loc.first
                        first.wait_for(state="visible", timeout=2500)
                        native_focus = False
                        try:
                            first.click(timeout=3500)
                        except Exception as click_exc:
                            if "Viewport size not available" not in repr(click_exc):
                                raise
                            # Cloak native-window mode has no emulated viewport;
                            # Playwright locator click/type can refuse to
                            # compute coordinates.  Focus only, then use the
                            # real keyboard path instead of setting .value.
                            first.evaluate(
                                """el => {
                                    el.scrollIntoView({block:'center', inline:'center'});
                                    el.focus();
                                }"""
                            )
                            native_focus = True
                        try:
                            page.keyboard.press("Control+A")
                            page.keyboard.press("Backspace")
                        except Exception:
                            try:
                                first.fill("", timeout=1200)
                            except Exception:
                                pass
                        try:
                            if native_focus:
                                page.keyboard.type(value, delay=max(8, 0.006 * self.wait_time))
                            else:
                                first.type(value, delay=max(8, 0.006 * self.wait_time), timeout=12000)
                        except Exception as type_exc:
                            if "Viewport size not available" not in repr(type_exc):
                                raise
                            first.evaluate(
                                """el => {
                                    el.scrollIntoView({block:'center', inline:'center'});
                                    el.focus();
                                }"""
                            )
                            page.keyboard.type(value, delay=max(8, 0.006 * self.wait_time))
                        page.wait_for_timeout(250)
                        try:
                            if (first.input_value(timeout=1200) or "").strip() == value:
                                return {"ok": True, "via": "trusted_type", "selector": selector}
                        except Exception:
                            return {"ok": True, "via": "trusted_type_unverified", "selector": selector}
                    except Exception:
                        continue
                try:
                    candidates = page.evaluate(
                        """() => {
                            const visible = (el) => {
                                if (!el) return false;
                                const r = el.getBoundingClientRect?.();
                                const s = getComputedStyle(el);
                                return !!r && r.width > 0 && r.height > 0 &&
                                    s.visibility !== 'hidden' && s.display !== 'none';
                            };
                            return [...document.querySelectorAll('input')]
                                .filter(visible)
                                .filter(el => {
                                    const type = String(el.getAttribute('type') || 'text').toLowerCase();
                                    return !['hidden', 'password', 'checkbox', 'radio', 'submit', 'button'].includes(type);
                                })
                                .map((el, idx) => ({
                                    idx,
                                    type: el.getAttribute('type') || '',
                                    name: el.name || '',
                                    id: el.id || '',
                                    dataTestid: el.getAttribute('data-testid') || '',
                                    autocomplete: el.getAttribute('autocomplete') || '',
                                    aria: el.getAttribute('aria-label') || '',
                                    placeholder: el.getAttribute('placeholder') || '',
                                    valueLen: String(el.value || '').length
                                }))
                                .slice(0, 12);
                        }"""
                    )
                except Exception:
                    candidates = []
                return {"ok": False, "reason": "trusted_input_not_found", "candidates": candidates}

            # The Microsoft data-export/consent gate can reappear or finish
            # rendering after the first entry check.  If we try to type email
            # while still on that gate, the generic input fallback burns a live
            # node before captcha is reached.  Re-run the consent click and
            # retry the email controls once before falling back to the legacy
            # localized aria selector.
            accept_initial_consent_gate(timeout_ms=8000)
            suffix_result = {"ok": False, "reason": "not_attempted"}
            email_result = {"ok": False, "reason": "not_attempted"}
            for email_attempt in range(1 if fast_fill else 2):
                if email_attempt:
                    print("[Email] retry after consent gate", flush=True)
                    accept_initial_consent_gate(timeout_ms=12000)
                    signup_email_entry_visible(timeout=8000)
                suffix_result = set_email_suffix_trusted(self.email_suffix)
                if isinstance(suffix_result, dict) and not suffix_result.get("ok"):
                    print(f"[Email] suffix target={self.email_suffix!r} result={suffix_result}", flush=True)
                if fast_fill:
                    email_result = fill_signup_email(email)
                    if isinstance(email_result, dict) and not email_result.get("ok"):
                        print(f"[SemiProtocolFill] email DOM fill failed: {email_result}; fallback to trusted type", flush=True)
                        email_result = type_signup_email_trusted(email)
                else:
                    email_result = type_signup_email_trusted(email)
                    if isinstance(email_result, dict) and not email_result.get("ok"):
                        if self.no_js_input_fallback:
                            print(f"[Email] trusted type failed: {email_result}; JS fallback disabled", flush=True)
                        else:
                            print(f"[Email] trusted type failed: {email_result}; using JS fallback", flush=True)
                            email_result = fill_signup_email(email)
                if not (isinstance(email_result, dict) and not email_result.get("ok")):
                    break
            if isinstance(email_result, dict) and not email_result.get("ok"):
                raise RuntimeError(f"email_input_not_found_after_consent_retry: {email_result}")
            if protocol_assist:
                if risk_initialize_cache and risk_initialize_cache.get("observed"):
                    print(
                        "[SemiProtocolFill] risk/initialize route snapshot "
                        f"status={risk_initialize_cache.get('status')} "
                        f"summary={risk_initialize_cache.get('responseSummary')}",
                        flush=True,
                    )
                else:
                    print(
                        "[SemiProtocolFill] risk/initialize route snapshot pending; "
                        "keeping natural UI request path",
                        flush=True,
                    )
                prefetch_mode = str(getattr(self, "signup_check_available_prefetch_mode", "sync") or "sync").lower()
                if prefetch_mode in {"off", "none", "disabled", "natural"}:
                    prefetch_result = {"ok": False, "reason": "disabled", "mode": prefetch_mode}
                    print(f"[SemiProtocolFill] CheckAvailable prefetch skipped mode={prefetch_mode}", flush=True)
                else:
                    prefetch_result = prefetch_check_available_protocol(f"{email}{self.email_suffix}")
                    print(f"[SemiProtocolFill] CheckAvailable prefetch result={prefetch_result}", flush=True)
                mark_fill_phase("email_ready", f"prefetch_mode={prefetch_mode} prefetch_ok={bool(isinstance(prefetch_result, dict) and prefetch_result.get('ok'))}")
            else:
                mark_fill_phase("email_ready")
            click_primary_button(timeout=12000, purpose="email")
            page.wait_for_timeout(
                int(getattr(self, "signup_fast_post_email_wait_ms", 250) or 0)
                if fast_fill
                else 0.02 * self.wait_time
            )
            mark_fill_phase("email_submitted")

            def set_password_dom_fast(value):
                try:
                    return page.evaluate(
                        """(value) => {
                            const visible = (el) => {
                                if (!el) return false;
                                const r = el.getBoundingClientRect?.();
                                const s = getComputedStyle(el);
                                return !!r && r.width > 0 && r.height > 0 &&
                                    s.visibility !== 'hidden' && s.display !== 'none' &&
                                    !el.disabled && el.getAttribute('aria-disabled') !== 'true';
                            };
                            const el = [...document.querySelectorAll('input[type="password"], input[name*="pass" i], input[id*="pass" i]')]
                                .find(visible);
                            if (!el) return {ok: false, reason: 'password_input_not_found'};
                            el.scrollIntoView({block:'center', inline:'center'});
                            el.focus();
                            const previous = el.value;
                            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
                            if (setter) setter.call(el, value); else el.value = value;
                            try { el._valueTracker && el._valueTracker.setValue(previous); } catch (_) {}
                            el.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:value}));
                            el.dispatchEvent(new Event('change', {bubbles:true}));
                            el.dispatchEvent(new Event('blur', {bubbles:true}));
                            return {ok: String(el.value || '') === String(value), valueLen: String(el.value || '').length};
                        }""",
                        password,
                    )
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:180]}

            last_password_error = None
            if fast_fill:
                page.wait_for_selector('[type="password"]', state="visible", timeout=12000)
                password_result = set_password_dom_fast(password)
                print(f"[SemiProtocolFill] password result={password_result}", flush=True)
                if isinstance(password_result, dict) and not password_result.get("ok"):
                    last_password_error = RuntimeError(f"password_dom_fast_failed: {password_result}")
            if last_password_error is not None or not fast_fill:
                last_password_error = None
                for password_attempt in range(3):
                    try:
                        page.wait_for_selector('[type="password"]', state="visible", timeout=12000)
                        pwd = page.locator('[type="password"]').last
                        native_viewport_focus = False
                        try:
                            pwd.click(timeout=6000)
                        except Exception as click_exc:
                            # Native CloakBrowser viewport mode can make
                            # Playwright report "Viewport size not available" even
                            # though the element is visible in the real window.
                            # Keep the browser-native viewport and focus via DOM
                            # instead of falling back to an emulated viewport.
                            if "Viewport size not available" not in repr(click_exc):
                                raise
                            pwd.evaluate("(el) => { el.scrollIntoView({block:'center', inline:'center'}); el.focus(); }")
                            native_viewport_focus = True
                        if native_viewport_focus:
                            page.keyboard.press("Control+A")
                            page.keyboard.press("Backspace")
                            page.keyboard.type(password, delay=max(8, 0.004 * self.wait_time))
                        else:
                            pwd.fill("")
                            pwd.type(password, delay=0.004 * self.wait_time, timeout=10000)
                        last_password_error = None
                        break
                    except Exception as exc:
                        last_password_error = exc
                        print(f"[Password] type attempt {password_attempt + 1}/3 failed: {exc!r}", flush=True)
                        page.wait_for_timeout(700 + password_attempt * 500)
            if last_password_error is not None:
                raise last_password_error
            page.wait_for_timeout(
                int(getattr(self, "signup_fast_pre_password_submit_wait_ms", 220) or 0)
                if fast_fill
                else 0.02 * self.wait_time
            )
            mark_fill_phase("password_ready")
            click_primary_button(timeout=12000, purpose="password")

            page.wait_for_timeout(
                int(getattr(self, "signup_fast_post_password_wait_ms", 300) or 0)
                if fast_fill
                else 0.03 * self.wait_time
            )
            mark_fill_phase("password_submitted")

            def set_signup_country(label):
                label = str(label or "").strip()
                if not label:
                    return {"ok": False, "reason": "empty"}
                try:
                    return page.evaluate(
                        """(label) => {
                            const visible = (el) => {
                                if (!el) return false;
                                const r = el.getBoundingClientRect?.();
                                const s = getComputedStyle(el);
                                return !!r && r.width > 0 && r.height > 0 &&
                                    s.visibility !== 'hidden' && s.display !== 'none';
                            };
                            const clean = (s) => String(s || '').replace(/\\s+/g, ' ').trim();
                            const textOf = (el) => [
                                el.getAttribute('name'),
                                el.id,
                                el.getAttribute('aria-label'),
                                el.getAttribute('placeholder'),
                                el.getAttribute('data-testid'),
                                el.closest('label')?.innerText,
                                el.innerText,
                                el.textContent
                            ].filter(Boolean).join(' ').trim();
                            const controls = [...document.querySelectorAll(
                                'select, input, [role="combobox"], button[aria-haspopup], button'
                            )].filter(visible);
                            const countryRe = /(country|region|国家|地区|國家|地區)/i;
                            let el =
                                document.querySelector('[name*="Country" i], #countryDropdownId, #countryDropdown, [aria-label*="国家"], [aria-label*="地区"], [aria-label*="country" i]') ||
                                controls.find(x => countryRe.test(textOf(x))) ||
                                controls[0] ||
                                null;
                            if (!visible(el)) return {ok: false, reason: 'country_not_found', controls: controls.map(textOf).slice(0, 8)};

                            if (String(el.tagName || '').toUpperCase() === 'SELECT') {
                                const opts = [...(el.options || [])];
                                const match = opts.find(opt => clean(opt.textContent) === label || clean(opt.textContent).includes(label) || String(opt.value || '') === label);
                                if (!match) return {ok: false, reason: 'option_not_found', current: clean(el.options?.[el.selectedIndex]?.textContent || el.value || ''), options: opts.map(opt => clean(opt.textContent)).filter(Boolean).slice(0, 20)};
                                const previous = el.value;
                                const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set;
                                if (setter) setter.call(el, match.value);
                                else el.value = match.value;
                                try { el._valueTracker && el._valueTracker.setValue(previous); } catch (_) {}
                                el.dispatchEvent(new Event('input', {bubbles: true}));
                                el.dispatchEvent(new Event('change', {bubbles: true}));
                                el.dispatchEvent(new Event('blur', {bubbles: true}));
                                return {ok: true, via: 'select', value: el.value, text: clean(match.textContent)};
                            }

                            el.scrollIntoView({block: 'center', inline: 'center'});
                            el.click();
                            return {ok: true, via: 'opened', current: clean(textOf(el)).slice(0, 160)};
                        }""",
                        label,
                    )
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:180]}

            def click_country_option(label):
                label = str(label or "").strip()
                if not label:
                    return {"ok": False, "reason": "empty"}
                try:
                    return page.evaluate(
                        """(label) => {
                            const visible = (el) => {
                                if (!el) return false;
                                const r = el.getBoundingClientRect?.();
                                const s = getComputedStyle(el);
                                return !!r && r.width > 0 && r.height > 0 &&
                                    s.visibility !== 'hidden' && s.display !== 'none';
                            };
                            const clean = (s) => String(s || '').replace(/\\s+/g, ' ').trim();
                            const optionSelectors = [
                                '[role="option"]',
                                '[role="menuitem"]',
                                '[aria-selected]',
                                '[role="listbox"] *',
                                '[id*="option" i]',
                                'div',
                                'span',
                                'button'
                            ];
                            const seen = new Set();
                            const nodes = [];
                            for (const sel of optionSelectors) {
                                try {
                                    for (const el of document.querySelectorAll(sel)) {
                                        if (seen.has(el)) continue;
                                        seen.add(el);
                                        if (visible(el)) nodes.push(el);
                                    }
                                } catch (_) {}
                            }
                            const match = nodes.find(el => clean(el.innerText || el.textContent) === label) ||
                                nodes.find(el => clean(el.innerText || el.textContent).includes(label));
                            if (!match) return {ok: false, reason: 'option_not_found', visible: nodes.map(el => clean(el.innerText || el.textContent)).filter(Boolean).slice(0, 30)};
                            match.scrollIntoView({block: 'center', inline: 'center'});
                            match.click();
                            return {ok: true, text: clean(match.innerText || match.textContent)};
                        }""",
                        label,
                    )
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:180]}

            if self.signup_country_label:
                country_result = set_signup_country(self.signup_country_label)
                if isinstance(country_result, dict) and country_result.get("via") == "opened":
                    page.wait_for_timeout(350)
                    option_result = click_country_option(self.signup_country_label)
                    if isinstance(option_result, dict) and option_result.get("ok"):
                        country_result = option_result
                page.wait_for_timeout(500)
                print(f"[DOB] country target={self.signup_country_label!r} result={country_result}", flush=True)

            def set_birth_input(selector, value):
                root = page.locator(selector)
                loc = root.first() if callable(getattr(root, "first", None)) else root.first
                try:
                    if loc.count() <= 0:
                        return False
                except Exception:
                    return False
                loc.wait_for(state="visible", timeout=10000)
                for _ in range(3):
                    try:
                        loc.click(timeout=3000)
                        loc.fill("", timeout=2500)
                        loc.type(value, delay=0.003 * self.wait_time, timeout=6000)
                        page.wait_for_timeout(
                            int(getattr(self, "signup_fast_birth_input_settle_ms", 180) or 0)
                            if fast_fill
                            else 180
                        )
                    except Exception:
                        pass
                    try:
                        if (loc.input_value(timeout=1000) or "").strip() == value:
                            return True
                    except Exception:
                        pass
                    try:
                        current = page.evaluate(
                            """({selector, value}) => {
                                const el = document.querySelector(selector);
                                if (!el) return null;
                                const previous = el.value;
                                const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
                                if (setter) setter.call(el, value);
                                else el.value = value;
                                try {
                                    const tracker = el._valueTracker;
                                    if (tracker) tracker.setValue(previous);
                                } catch (_) {}
                                el.dispatchEvent(new InputEvent('input', {bubbles: true, inputType: 'insertText', data: value}));
                                el.dispatchEvent(new Event('change', {bubbles: true}));
                                el.dispatchEvent(new Event('blur', {bubbles: true}));
                                return el.value;
                            }""",
                            {"selector": selector, "value": value},
                        )
                        if str(current or "").strip() == value:
                            return True
                    except Exception:
                        pass
                    page.wait_for_timeout(220)
                return False

            def set_birth_select(selector, value):
                root = page.locator(selector)
                loc = root.first() if callable(getattr(root, "first", None)) else root.first
                try:
                    if loc.count() <= 0:
                        return False
                except Exception:
                    return False
                loc.wait_for(state="visible", timeout=10000)
                try:
                    tag_name = loc.evaluate("el => String(el.tagName || '').toUpperCase()")
                    if tag_name != "SELECT":
                        return False
                except Exception:
                    return False
                for _ in range(3):
                    suffix = "月" if "Month" in selector else "日"
                    labels = [f"{int(value)}{suffix}", f"{value}{suffix}", str(value)]
                    if "Month" in selector:
                        month_names = [
                            "January", "February", "March", "April", "May", "June",
                            "July", "August", "September", "October", "November", "December",
                        ]
                        try:
                            month_name = month_names[int(value) - 1]
                            labels.extend([month_name, month_name[:3]])
                        except Exception:
                            pass
                    value_candidates = [str(value), f"{int(value):02d}"] + labels
                    try:
                        for candidate in value_candidates:
                            try:
                                loc.select_option(value=candidate, timeout=1200)
                                page.wait_for_timeout(
                                    int(getattr(self, "signup_fast_birth_select_settle_ms", 120) or 0)
                                    if fast_fill
                                    else 120
                                )
                                break
                            except Exception:
                                try:
                                    loc.select_option(label=candidate, timeout=1200)
                                    page.wait_for_timeout(
                                        int(getattr(self, "signup_fast_birth_select_settle_ms", 120) or 0)
                                        if fast_fill
                                        else 120
                                    )
                                    break
                                except Exception:
                                    continue
                    except Exception:
                        pass
                    try:
                        current = page.evaluate(
                            """({selector, value}) => {
                                const el = document.querySelector(selector);
                                if (!el) return null;
                                const suffix = /Month/i.test(selector) ? '月' : '日';
                                const wanted = String(value);
                                const labels = [
                                    wanted,
                                    wanted.padStart(2, '0'),
                                    `${parseInt(wanted, 10)}${suffix}`,
                                    `${wanted}${suffix}`
                                ];
                                if (/Month/i.test(selector)) {
                                    const monthNames = [
                                        'January', 'February', 'March', 'April', 'May', 'June',
                                        'July', 'August', 'September', 'October', 'November', 'December'
                                    ];
                                    const monthName = monthNames[parseInt(wanted, 10) - 1];
                                    if (monthName) labels.push(monthName, monthName.slice(0, 3));
                                }
                                const optionText = (opt) => String(opt?.textContent || '').trim();
                                let finalValue = wanted;
                                if (el.options) {
                                    const match = [...el.options].find(opt => {
                                        const ov = String(opt.value || '');
                                        const ot = optionText(opt);
                                        return labels.includes(ov) || labels.includes(ot) || labels.some(x => ot.includes(x));
                                    });
                                    if (match) finalValue = String(match.value || '');
                                }
                                if (String(el.value) !== finalValue) {
                                    const previous = el.value;
                                    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set;
                                    if (setter) setter.call(el, finalValue);
                                    else el.value = finalValue;
                                    try {
                                        const tracker = el._valueTracker;
                                        if (tracker) tracker.setValue(previous);
                                    } catch (_) {}
                                    el.dispatchEvent(new Event('input', {bubbles: true}));
                                    el.dispatchEvent(new Event('change', {bubbles: true}));
                                }
                                const selected = el.options ? el.options[el.selectedIndex] : null;
                                const selectedText = optionText(selected);
                                return {
                                    value: el.value,
                                    text: selectedText,
                                    ok: labels.includes(String(el.value || '')) ||
                                        labels.includes(selectedText) ||
                                        labels.some(x => selectedText.includes(x))
                                };
                            }""",
                            {"selector": selector, "value": value},
                        )
                        if isinstance(current, dict) and current.get("ok"):
                            return True
                    except Exception:
                        pass
                    try:
                        loc.click(timeout=2500)
                        page.wait_for_timeout(
                            int(getattr(self, "signup_fast_birth_select_settle_ms", 120) or 0)
                            if fast_fill
                            else 180
                        )
                        for label in labels:
                            try:
                                option = page.locator(f'[role="option"]:text-is("{label}")')
                                if option.count() > 0:
                                    option.click(timeout=2500)
                                    page.wait_for_timeout(
                                        int(getattr(self, "signup_fast_birth_select_settle_ms", 120) or 0)
                                        if fast_fill
                                        else 180
                                    )
                                    break
                            except Exception:
                                continue
                    except Exception:
                        pass
                    try:
                        current = page.evaluate(
                            """({selector, value}) => {
                                const el = document.querySelector(selector);
                                if (!el) return {value: '', text: '', ok: false};
                                const suffix = /Month/i.test(selector) ? '月' : '日';
                                const wanted = String(value);
                                const labels = [wanted, wanted.padStart(2, '0'), `${parseInt(wanted, 10)}${suffix}`, `${wanted}${suffix}`];
                                if (/Month/i.test(selector)) {
                                    const monthNames = [
                                        'January', 'February', 'March', 'April', 'May', 'June',
                                        'July', 'August', 'September', 'October', 'November', 'December'
                                    ];
                                    const monthName = monthNames[parseInt(wanted, 10) - 1];
                                    if (monthName) labels.push(monthName, monthName.slice(0, 3));
                                }
                                const selected = el.options ? el.options[el.selectedIndex] : null;
                                const text = String(selected?.textContent || '').trim();
                                return {
                                    value: el.value || '',
                                    text,
                                    ok: labels.includes(String(el.value || '')) || labels.includes(text) || labels.some(x => text.includes(x))
                                };
                            }""",
                            {"selector": selector, "value": value},
                        )
                        if isinstance(current, dict) and current.get("ok"):
                            return True
                    except Exception:
                        pass
                    page.wait_for_timeout(
                        int(getattr(self, "signup_fast_birth_select_settle_ms", 120) or 0)
                        if fast_fill
                        else 220
                    )
                return False

            def set_birth_combo(label, value, suffix):
                """
                New Fluent signup builds sometimes render month/day as custom
                comboboxes instead of real <select name=BirthDay>.  Keep this
                as a narrow fallback: open the visible control and choose the
                exact option text if it is present.
                """
                value = str(value)
                try:
                    numeric = int(value)
                except Exception:
                    numeric = None
                labels = []
                if numeric is not None:
                    labels.extend([
                        f"{numeric}{suffix}",
                        f"{numeric:02d}{suffix}",
                        str(numeric),
                        f"{numeric:02d}",
                    ])
                    if suffix == "月":
                        month_names = [
                            "January", "February", "March", "April", "May", "June",
                            "July", "August", "September", "October", "November", "December",
                        ]
                        try:
                            month_name = month_names[numeric - 1]
                            labels.extend([month_name, month_name[:3]])
                        except Exception:
                            pass
                labels.extend([value, f"{value}{suffix}"])
                # Preserve order while de-duplicating.
                labels = list(dict.fromkeys(labels))

                def open_combo():
                    kind = "month" if suffix == "月" else "day"
                    try:
                        opened = page.evaluate(
                            """({label, kind}) => {
                                const visible = (el) => {
                                    if (!el) return false;
                                    const r = el.getBoundingClientRect?.();
                                    const s = getComputedStyle(el);
                                    return !!r && r.width > 0 && r.height > 0 &&
                                        s.visibility !== 'hidden' && s.display !== 'none';
                                };
                                const textOf = (el) => [
                                    el.getAttribute('name'),
                                    el.id,
                                    el.getAttribute('aria-label'),
                                    el.getAttribute('placeholder'),
                                    el.getAttribute('data-testid'),
                                    el.closest('label')?.innerText,
                                    el.textContent
                                ].filter(Boolean).join(' ').trim();
                                const controls = [...document.querySelectorAll(
                                    'select, input, [role="combobox"], button[aria-haspopup], button'
                                )].filter(visible);
                                const labelRe = kind === 'month'
                                    ? /(BirthMonth|month|月份|月)/i
                                    : /(BirthDay|day|日期|日)/i;
                                let el =
                                    document.querySelector(kind === 'month'
                                        ? '[name="BirthMonth"], #BirthMonth, [aria-label="月"], [placeholder="月"]'
                                        : '[name="BirthDay"], #BirthDay, [aria-label="日"], [placeholder="日"]');
                                if (!visible(el)) {
                                    el = controls.find(x => labelRe.test(textOf(x)));
                                }
                                if (!visible(el)) {
                                    // Observed Fluent order: country, year,
                                    // month, day.  This is only a fallback.
                                    const compact = [...document.querySelectorAll('select, input, [role="combobox"]')]
                                        .filter(visible);
                                    el = compact[kind === 'month' ? 2 : 3] || null;
                                }
                                if (!visible(el)) return {ok: false, reason: 'not_found', controls: controls.map(textOf).slice(0, 12)};
                                el.scrollIntoView({block: 'center', inline: 'center'});
                                el.click();
                                return {ok: true, tag: el.tagName, role: el.getAttribute('role'), text: textOf(el).slice(0, 160)};
                            }""",
                            {"label": label, "kind": kind},
                        )
                        if isinstance(opened, dict) and opened.get("ok"):
                            return opened
                    except Exception:
                        pass

                    # Playwright accessible-name fallback.
                    openers = [
                        lambda: page.get_by_label(label, exact=True),
                        lambda: page.locator(f'[aria-label="{label}"]'),
                        lambda: page.locator(f'[placeholder="{label}"]'),
                        lambda: page.locator('[role="combobox"]').filter(has_text=label),
                    ]
                    for build in openers:
                        try:
                            loc = build()
                            loc = loc.first() if callable(getattr(loc, "first", None)) else loc.first
                            if loc.count() > 0:
                                loc.click(timeout=2500)
                                return {"ok": True, "via": "locator"}
                        except Exception:
                            continue
                    return {"ok": False, "reason": "locator_not_found"}

                for _ in range(3):
                    opened = open_combo()
                    page.wait_for_timeout(220)
                    if not opened or not opened.get("ok"):
                        page.wait_for_timeout(250)
                        continue
                    try:
                        clicked = page.evaluate(
                            """(labels) => {
                                const visible = (el) => {
                                    if (!el) return false;
                                    const r = el.getBoundingClientRect?.();
                                    const s = getComputedStyle(el);
                                    return !!r && r.width > 0 && r.height > 0 &&
                                        s.visibility !== 'hidden' && s.display !== 'none';
                                };
                                const clean = (s) => String(s || '').replace(/\\s+/g, ' ').trim();
                                const labelSet = new Set(labels.map(clean));
                                const optionSelectors = [
                                    '[role="option"]',
                                    '[role="menuitem"]',
                                    '[aria-selected]',
                                    '[role="listbox"] *',
                                    '[id*="option" i]',
                                    'div',
                                    'span',
                                    'button'
                                ];
                                const seen = new Set();
                                const nodes = [];
                                for (const sel of optionSelectors) {
                                    try {
                                        for (const el of document.querySelectorAll(sel)) {
                                            if (seen.has(el)) continue;
                                            seen.add(el);
                                            if (visible(el)) nodes.push(el);
                                        }
                                    } catch (_) {}
                                }
                                const match = nodes.find(el => labelSet.has(clean(el.innerText || el.textContent)));
                                if (!match) {
                                    return {
                                        ok: false,
                                        visible: nodes.map(el => clean(el.innerText || el.textContent)).filter(Boolean).slice(0, 24)
                                    };
                                }
                                match.scrollIntoView({block: 'center', inline: 'center'});
                                match.click();
                                return {ok: true, text: clean(match.innerText || match.textContent)};
                            }""",
                            labels,
                        )
                        if isinstance(clicked, dict) and clicked.get("ok"):
                            page.wait_for_timeout(300)
                            return True
                    except Exception:
                        pass
                    for candidate in labels:
                        try:
                            opt = page.locator(f'[role="option"]:text-is("{candidate}")')
                            if opt.count() > 0:
                                first = opt.first() if callable(getattr(opt, "first", None)) else opt.first
                                first.click(timeout=3500)
                                page.wait_for_timeout(220)
                                return True
                        except Exception:
                            pass
                        try:
                            opt = page.get_by_role("option", name=candidate, exact=True)
                            if opt.count() > 0:
                                first = opt.first() if callable(getattr(opt, "first", None)) else opt.first
                                first.click(timeout=3500)
                                page.wait_for_timeout(220)
                                return True
                        except Exception:
                            pass
                        try:
                            opt = page.get_by_text(candidate, exact=True)
                            if opt.count() > 0:
                                first = opt.first() if callable(getattr(opt, "first", None)) else opt.first
                                first.click(timeout=3500)
                                page.wait_for_timeout(220)
                                return True
                        except Exception:
                            pass
                    try:
                        page.keyboard.press("Escape")
                    except Exception:
                        pass
                    page.wait_for_timeout(250)
                return False

            def set_birth_dom_fallback():
                try:
                    return page.evaluate(
                        """({year, month, day}) => {
                            const visible = (el) => {
                                if (!el) return false;
                                const r = el.getBoundingClientRect?.();
                                const s = getComputedStyle(el);
                                return !!r && r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                            };
                            const textOf = (el) => [
                                el.getAttribute('name'),
                                el.id,
                                el.getAttribute('aria-label'),
                                el.getAttribute('placeholder'),
                                el.getAttribute('data-testid'),
                                el.closest('label')?.innerText
                            ].filter(Boolean).join(' ').toLowerCase();
                            const pickOptionValue = (el, value, suffix) => {
                                if (!el || !el.options) return String(value);
                                const labels = [`${parseInt(value, 10)}${suffix}`, `${value}${suffix}`, String(value), String(value).padStart(2, '0')];
                                if (suffix === '月') {
                                    const monthNames = [
                                        'January', 'February', 'March', 'April', 'May', 'June',
                                        'July', 'August', 'September', 'October', 'November', 'December'
                                    ];
                                    const monthName = monthNames[parseInt(value, 10) - 1];
                                    if (monthName) labels.push(monthName, monthName.slice(0, 3));
                                }
                                for (const opt of [...el.options]) {
                                    const ov = String(opt.value || '');
                                    const ot = String(opt.textContent || '').trim();
                                    if (labels.includes(ov) || labels.includes(ot) || labels.some(x => ot.includes(x))) return ov;
                                }
                                return String(value);
                            };
                            const setValue = (el, value, proto, suffix) => {
                                if (!el) return false;
                                const previous = el.value;
                                const finalValue = el.tagName === 'SELECT' ? pickOptionValue(el, value, suffix || '') : String(value);
                                const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
                                if (setter) setter.call(el, finalValue);
                                else el.value = finalValue;
                                try {
                                    const tracker = el._valueTracker;
                                    if (tracker) tracker.setValue(previous);
                                } catch (_) {}
                                el.dispatchEvent(new Event('input', {bubbles: true}));
                                el.dispatchEvent(new Event('change', {bubbles: true}));
                                el.dispatchEvent(new Event('blur', {bubbles: true}));
                                return true;
                            };
                            const inputs = [...document.querySelectorAll('input')].filter(visible);
                            const selects = [...document.querySelectorAll('select')].filter(visible);
                            const yearEl =
                                document.querySelector('[name="BirthYear"], #BirthYear, input[name*="Year"], input[id*="Year"]') ||
                                inputs.find(el => /birth.*year|year|yyyy|年份|年/.test(textOf(el))) ||
                                inputs.find(el => ['text', 'number', 'tel'].includes((el.type || '').toLowerCase()));
                            const monthEl =
                                document.querySelector('[name="BirthMonth"], #BirthMonth, select[name*="Month"], select[id*="Month"]') ||
                                selects.find(el => /birth.*month|month|月份|月/.test(textOf(el))) ||
                                selects[1] || selects[0];
                            const dayEl =
                                document.querySelector('[name="BirthDay"], #BirthDay, select[name*="Day"], select[id*="Day"]') ||
                                selects.find(el => /birth.*day|day|日期|日/.test(textOf(el))) ||
                                selects[2] || selects[1];
                            setValue(monthEl, month, HTMLSelectElement.prototype, '月');
                            setValue(dayEl, day, HTMLSelectElement.prototype, '日');
                            setValue(yearEl, year, HTMLInputElement.prototype, '');
                            return {
                                inputCount: inputs.length,
                                selectCount: selects.length,
                                year: yearEl ? yearEl.value : '',
                                month: monthEl ? monthEl.value : '',
                                day: dayEl ? dayEl.value : '',
                                yearMeta: yearEl ? textOf(yearEl).slice(0, 160) : '',
                                monthMeta: monthEl ? textOf(monthEl).slice(0, 160) : '',
                                dayMeta: dayEl ? textOf(dayEl).slice(0, 160) : ''
                            };
                        }""",
                        {"year": year, "month": month, "day": day},
                    )
                except Exception:
                    return {}

            def get_birth_values():
                try:
                    return page.evaluate(
                        """() => {
                            const visible = (el) => {
                                if (!el) return false;
                                const r = el.getBoundingClientRect?.();
                                const s = getComputedStyle(el);
                                return !!r && r.width > 0 && r.height > 0 &&
                                    s.visibility !== 'hidden' && s.display !== 'none';
                            };
                            const textOf = (el) => [
                                el.getAttribute('name'),
                                el.id,
                                el.getAttribute('aria-label'),
                                el.getAttribute('placeholder'),
                                el.getAttribute('data-testid'),
                                el.closest('label')?.innerText,
                                el.textContent
                            ].filter(Boolean).join(' ').trim();
                            const valueOf = (el, placeholder) => {
                                if (!el) return '';
                                let raw = '';
                                if ('value' in el && el.value) raw = String(el.value);
                                if (!raw) raw = String(el.innerText || el.textContent || '');
                                raw = raw.replace(/\\s+/g, ' ').trim();
                                if (!raw || raw === placeholder) return '';
                                const m = raw.match(/\\d{1,4}/);
                                return m ? m[0].replace(/^0+(?=\\d)/, '') : raw;
                            };
                            const controls = [...document.querySelectorAll('select, input, [role="combobox"]')]
                                .filter(visible);
                            const pick = (re, fallbackIndex) => (
                                controls.find(el => re.test(textOf(el))) ||
                                controls[fallbackIndex] ||
                                null
                            );
                            const yearEl =
                                document.querySelector('[name="BirthYear"], #BirthYear, input[name*="Year"], input[id*="Year"]') ||
                                pick(/birth.*year|year|yyyy|年份|年/i, 1);
                            const monthEl =
                                document.querySelector('[name="BirthMonth"], #BirthMonth, select[name*="Month"], select[id*="Month"]') ||
                                pick(/birth.*month|month|月份|月/i, 2);
                            const dayEl =
                                document.querySelector('[name="BirthDay"], #BirthDay, select[name*="Day"], select[id*="Day"]') ||
                                pick(/birth.*day|day|日期|日/i, 3);
                            return {
                                year: valueOf(yearEl, '年份'),
                                month: valueOf(monthEl, '月'),
                                day: valueOf(dayEl, '日'),
                                controls: controls.map(el => textOf(el).slice(0, 120)).slice(0, 8)
                            };
                        }"""
                    )
                except Exception:
                    return {}

            def wait_for_birth_controls_fast(timeout_ms=None):
                timeout_ms = int(
                    timeout_ms
                    if timeout_ms is not None
                    else getattr(self, "signup_fast_dob_ready_wait_ms", 0) or 0
                )
                if timeout_ms <= 0:
                    return {"ok": False, "reason": "disabled"}
                started_wait = time.time()
                try:
                    page.wait_for_function(
                        """() => {
                            const visible = (el) => {
                                if (!el) return false;
                                const r = el.getBoundingClientRect?.();
                                const s = getComputedStyle(el);
                                return !!r && r.width > 0 && r.height > 0 &&
                                    s.visibility !== 'hidden' && s.display !== 'none' &&
                                    !el.disabled && el.getAttribute('aria-disabled') !== 'true';
                            };
                            const textOf = (el) => [
                                el.getAttribute('name'),
                                el.id,
                                el.getAttribute('aria-label'),
                                el.getAttribute('placeholder'),
                                el.getAttribute('data-testid'),
                                el.closest('label')?.innerText,
                                el.innerText,
                                el.textContent
                            ].filter(Boolean).join(' ').toLowerCase();
                            const controls = [...document.querySelectorAll('select, input, [role="combobox"]')]
                                .filter(visible);
                            const year = controls.find(el => /birth.*year|year|yyyy|年份|年/.test(textOf(el)));
                            const month = controls.find(el => /birth.*month|month|月份|月/.test(textOf(el))) ||
                                document.querySelector('[name="BirthMonth"], #BirthMonth, select[name*="Month"], select[id*="Month"]');
                            const day = controls.find(el => /birth.*day|day|日期|日/.test(textOf(el))) ||
                                document.querySelector('[name="BirthDay"], #BirthDay, select[name*="Day"], select[id*="Day"]');
                            return !!(year && visible(month) && visible(day));
                        }""",
                        timeout=max(250, timeout_ms),
                    )
                    return {"ok": True, "ms": int((time.time() - started_wait) * 1000)}
                except Exception as exc:
                    return {"ok": False, "ms": int((time.time() - started_wait) * 1000), "reason": repr(exc)[:160]}

            def dob_value_matches(current, expected):
                current = str(current or "").strip()
                expected = str(expected or "").strip()
                if current == expected:
                    return True
                try:
                    return int(current) == int(expected)
                except Exception:
                    return False

            def dob_values_match(values):
                if not isinstance(values, dict):
                    return False
                return (
                    dob_value_matches(values.get("year"), year)
                    and dob_value_matches(values.get("month"), month)
                    and dob_value_matches(values.get("day"), day)
                )

            dob_attempt_count = 2 if fast_fill else 4
            if fast_fill:
                birth_ready = wait_for_birth_controls_fast()
                if birth_ready.get("ok") or int(getattr(self, "signup_fast_dob_ready_wait_ms", 0) or 0) > 0:
                    print(f"[DOB] fast ready wait result={birth_ready}", flush=True)
            for dob_attempt in range(dob_attempt_count):
                fallback_values = set_birth_dom_fallback()
                if fast_fill and dob_values_match(fallback_values):
                    # In the current Fluent build the single in-page setter is
                    # usually enough.  Avoid re-clicking the month/day controls
                    # because that costs 1-2s and can itself trigger re-renders.
                    values = get_birth_values()
                else:
                    if not set_birth_select('[name="BirthMonth"]', month):
                        set_birth_combo("月", month, "月")
                    set_birth_input('[name="BirthYear"]', year)
                    # Month/year changes can re-render the day drop-down and reset
                    # it to the placeholder.  Always set day last, then verify.
                    if not set_birth_select('[name="BirthDay"]', day):
                        set_birth_combo("日", day, "日")
                    values = get_birth_values()
                if not values.get("day"):
                    page.wait_for_timeout(
                        int(getattr(self, "signup_fast_birth_select_settle_ms", 120) or 0)
                        if fast_fill
                        else 250
                    )
                    set_birth_dom_fallback()
                    if not set_birth_select('[name="BirthDay"]', day):
                        set_birth_combo("日", day, "日")
                    values = get_birth_values()
                print(
                    f"[DOB] attempt {dob_attempt + 1}: "
                    f"target={{'year': {year!r}, 'month': {month!r}, 'day': {day!r}}} "
                    f"fallback={fallback_values} "
                    f"named={{'year': {values.get('year')!r}, 'month': {values.get('month')!r}, 'day': {values.get('day')!r}}} "
                    f"controls={values.get('controls')!r}",
                    flush=True,
                )
                if not values.get("year") or not values.get("month") or not values.get("day"):
                    if dob_attempt == dob_attempt_count - 1:
                        raise TimeoutError(f"DOB fields not stable: {values!r}")
                    page.wait_for_timeout(
                        max(120, int(getattr(self, "signup_fast_birth_select_settle_ms", 120) or 0))
                        if fast_fill
                        else 650
                    )
                    continue
                click_primary_button(timeout=10000, purpose="dob")
                try:
                    page.wait_for_function(
                        """() => {
                            const el = document.querySelector('#lastNameInput');
                            if (!el) return false;
                            const r = el.getBoundingClientRect?.();
                            const s = getComputedStyle(el);
                            return !!r && r.width > 0 && r.height > 0 &&
                                s.visibility !== 'hidden' && s.display !== 'none';
                        }""",
                        timeout=7000,
                    )
                    break
                except Exception:
                    if dob_attempt == dob_attempt_count - 1:
                        raise
                    page.wait_for_timeout(
                        max(120, int(getattr(self, "signup_fast_birth_select_settle_ms", 120) or 0))
                        if fast_fill
                        else 650
                    )

            mark_fill_phase("dob_submitted")

            def set_names_dom_fast(first, last):
                try:
                    return page.evaluate(
                        """({first, last}) => {
                            const setOne = (selector, value) => {
                                const el = document.querySelector(selector);
                                if (!el) return false;
                                el.scrollIntoView({block:'center', inline:'center'});
                                el.focus();
                                const previous = el.value;
                                const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
                                if (setter) setter.call(el, value); else el.value = value;
                                try { el._valueTracker && el._valueTracker.setValue(previous); } catch (_) {}
                                el.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:value}));
                                el.dispatchEvent(new Event('change', {bubbles:true}));
                                el.dispatchEvent(new Event('blur', {bubbles:true}));
                                return String(el.value || '') === String(value);
                            };
                            const lastOk = setOne('#lastNameInput', last);
                            const firstOk = setOne('#firstNameInput', first);
                            return {ok: !!lastOk && !!firstOk, firstOk, lastOk};
                        }""",
                        {"first": firstname, "last": lastname},
                    )
                except Exception as exc:
                    return {"ok": False, "reason": repr(exc)[:180]}

            names_fast_result = set_names_dom_fast(firstname, lastname) if fast_fill else {"ok": False, "reason": "disabled"}
            if fast_fill:
                print(f"[SemiProtocolFill] names result={names_fast_result}", flush=True)
            if not (fast_fill and isinstance(names_fast_result, dict) and names_fast_result.get("ok")):
                try:
                    page.locator('#lastNameInput').type(lastname, delay=0.002 * self.wait_time, timeout=10000)
                except Exception as exc:
                    if "Viewport size not available" not in repr(exc):
                        raise
                    page.evaluate(
                        """(value) => {
                            const el = document.querySelector('#lastNameInput');
                            if (!el) throw new Error('lastNameInput not found');
                            el.scrollIntoView({block:'center', inline:'center'});
                            el.focus();
                            const previous = el.value;
                            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
                            if (setter) setter.call(el, value); else el.value = value;
                            try { el._valueTracker && el._valueTracker.setValue(previous); } catch (_) {}
                            el.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:value}));
                            el.dispatchEvent(new Event('change', {bubbles:true}));
                        }""",
                        lastname,
                    )
                page.wait_for_timeout(0.02 * self.wait_time)
                try:
                    page.locator('#firstNameInput').fill(firstname, timeout=10000)
                except Exception as exc:
                    if "Viewport size not available" not in repr(exc):
                        raise
                    page.evaluate(
                        """(value) => {
                            const el = document.querySelector('#firstNameInput');
                            if (!el) throw new Error('firstNameInput not found');
                            el.scrollIntoView({block:'center', inline:'center'});
                            el.focus();
                            const previous = el.value;
                            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
                            if (setter) setter.call(el, value); else el.value = value;
                            try { el._valueTracker && el._valueTracker.setValue(previous); } catch (_) {}
                            el.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:value}));
                            el.dispatchEvent(new Event('change', {bubbles:true}));
                        }""",
                        firstname,
                    )
            else:
                page.wait_for_timeout(int(getattr(self, "signup_fast_name_ready_wait_ms", 120) or 0))

            mark_fill_phase("names_ready")

            if (not fast_fill) and time.time() - start_time < self.wait_time / 1000:
                page.wait_for_timeout(self.wait_time - (time.time() - start_time) * 1000)

            submit_state = "timeout"
            for name_submit_attempt in range(2 if fast_fill else 3):
                name_submit_mode = str(getattr(self, "signup_name_submit_mode", "native") or "native").lower()
                click_primary_button(
                    timeout=10000,
                    force_native=(fast_fill and name_submit_mode in {"native", "playwright", "ui"}),
                    purpose="name",
                )
                submit_state = wait_after_name_submit(
                    timeout_ms=(
                        int(getattr(self, "signup_fast_name_submit_wait_ms", 9000) or 9000)
                        if fast_fill
                        else 12000
                    )
                )
                print(f"[Name] submit attempt {name_submit_attempt + 1}: state={submit_state}")
                if submit_state in ("create_account", "challenge", "left_name_page", "blocked"):
                    break
                page.wait_for_timeout(350 if fast_fill else 700)
            mark_fill_phase("name_submitted", f"state={submit_state}")
            if submit_state == "timeout":
                print("[Error: Submit] - 姓名页提交后未观察到验证码、CreateAccount 或页面切换。")
                self.save_diagnostic(page, "name_submit_stuck", email)
                return False
            # Older code waited for the footer terms link to detach here.
            # Recent Fluent signup builds keep that footer across multiple
            # views, so this wait can stall the whole run after a successful
            # name submit.  The explicit wait_after_name_submit() state check
            # above is the authoritative transition signal now.
            page.wait_for_timeout(
                int(getattr(self, "signup_fast_post_name_submit_buffer_ms", 400) or 0)
                if fast_fill
                else 400
            )

            if submit_state == "left_name_page":
                transition_deadline = time.time() + 15
                while time.time() < transition_deadline:
                    if create_account_requested_or_done():
                        submit_state = "create_account"
                        break
                    if hs_challenge_visible():
                        submit_state = "challenge"
                        break
                    if page.get_by_text('账户创建已被阻止').count() or page.get_by_text('一些异常活动').count():
                        submit_state = "blocked"
                        break
                    page.wait_for_timeout(500)
                print(f"[Name] post-left transition state={submit_state}")

            if page.get_by_text('一些异常活动').count() or page.get_by_text('此站点正在维护，暂时无法使用，请稍后重试。').count() > 0:
                print("[Error: IP or browser] - 当前IP注册频率过快。检查IP与是否为指纹浏览器并关闭了无头模式。")
                self.save_diagnostic(page, "abnormal_activity", email)
                return False

            if page.locator('iframe#enforcementFrame').count() > 0:
                print("[Error: FunCaptcha] - 验证码类型错误，非按压验证码。")
                self.save_diagnostic(page, "funcaptcha", email)
                return False

            if self.capture_challenge:
                self.save_challenge_snapshot(page, email)

            if self.manual_captcha:
                finalize_captcha_events = self.attach_captcha_event_logger(page, email)
                print(f"[Manual] - 已进入人机验证阶段，请在浏览器里手动完成验证；最多等待 {self.manual_captcha_wait_seconds} 秒。")
                deadline = time.time() + self.manual_captcha_wait_seconds
                manual_challenge_cleared = False
                while time.time() < deadline:
                    if page.get_by_text('账户创建已被阻止').count() or page.get_by_text('一些异常活动').count():
                        self.save_diagnostic(page, "manual_blocked", email)
                        if finalize_captcha_events:
                            finalize_captcha_events()
                        return False

                    challenge_visible = hs_challenge_visible()
                    if not challenge_visible:
                        manual_challenge_cleared = True
                        break
                    page.wait_for_timeout(1000)
                else:
                    self.save_diagnostic(page, "manual_timeout", email)
                    if finalize_captcha_events:
                        finalize_captcha_events()
                    return False

                if manual_challenge_cleared and self.manual_post_verify_wait_seconds > 0:
                    page.wait_for_timeout(self.manual_post_verify_wait_seconds * 1000)
                    if page.get_by_text('账户创建已被阻止').count() or page.get_by_text('一些异常活动').count():
                        self.save_diagnostic(page, "manual_post_blocked", email)
                        if finalize_captcha_events:
                            finalize_captcha_events()
                        return False
                if finalize_captcha_events:
                    finalize_captcha_events()
            else:
                if hs_challenge_visible():
                    captcha_result = self.handle_captcha(page)
                    if not captcha_result:
                        # A fast successful proof can navigate away while the
                        # captcha handler is still polling iframe/locator state
                        # (Playwright then raises "execution context was
                        # destroyed").  The network logger is authoritative:
                        # if CreateAccount already returned a success body, do not burn a
                        # successful account as captcha_failed.
                        account_ok, account_state = self.wait_for_create_account_success(page, timeout_ms=8000)
                        if account_ok:
                            print(
                                "[Captcha] - handler reported failure after CreateAccount success body; "
                                "treating captcha as completed.",
                                flush=True,
                            )
                        else:
                            print(
                                f"[Captcha] - handler failed and no CreateAccount success body observed. "
                                f"state={account_state}",
                                flush=True,
                            )
                            self.save_diagnostic(page, "captcha_failed", email)
                            raise TimeoutError
                    if self.post_captcha_account_wait_seconds > 0:
                        page.wait_for_timeout(self.post_captcha_account_wait_seconds * 1000)
                        if page.get_by_text('账户创建已被阻止').count() or page.get_by_text('一些异常活动').count():
                            self.save_diagnostic(page, "post_captcha_blocked", email)
                            return False
                else:
                    print("[Captcha] - 未观察到可见长按验证，转为等待 CreateAccount。")

            mark_fill_phase("captcha_phase_done")
            account_ok, account_state = self.wait_for_create_account_success(page, timeout_ms=28000)
            if not account_ok:
                print(f"[Error: CreateAccount] - 未观察到 CreateAccount 成功响应体，避免误判成功。 state={account_state}")
                self.save_diagnostic(page, "registration_not_completed", email)
                return False

        except Exception as exc:
            print(f"[Error: IP] - 加载超时或因触发机器人检测导致按压次数达到最大仍未通过。 detail={exc!r}")
            self.save_diagnostic(page, "register_exception", email)
            return False

        return finalize_registration_success()
