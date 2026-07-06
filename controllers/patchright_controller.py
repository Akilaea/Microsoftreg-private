import os
import random
import time
import math
from patchright.sync_api import sync_playwright
from .base_controller import BaseBrowserController
from settings import load_config


class _NoopPlaywright:
    def stop(self):
        return None


class PatchrightController(BaseBrowserController):

    def __init__(self):
        super().__init__()
        data = load_config()
        patchright_config = data.get("patchright", {})
        self.browser_path = patchright_config.get("browser_path") or data.get("playwright", {}).get("browser_path", "")
        self.user_data_dir = patchright_config.get("user_data_dir", "")
        if self.user_data_dir:
            self.user_data_dir = os.path.abspath(self.user_data_dir)
        self.cdp_endpoint = patchright_config.get("cdp_endpoint") or data.get("cdp_endpoint", "")
        self.cdp_keep_open = bool(patchright_config.get("cdp_keep_open", True))
        self.connected_over_cdp = False
        self.use_cloakbrowser = bool(patchright_config.get("use_cloakbrowser", False))
        self.extra_args = list(patchright_config.get("args") or [])
        self.cloakbrowser_options = data.get("cloakbrowser", {})
        self.headless = bool(
            patchright_config.get("headless", data.get("headless", False))
            or str(os.environ.get("OUTLOOK_REGISTER_HEADLESS", "")).lower() in {"1", "true", "yes", "on"}
        )
        self._last_mouse_pos = None

    def launch_browser(self):
        try:
            p = sync_playwright().start() 

            if self.cdp_endpoint:
                # Fingerprint browsers such as CloakBrowser already own the
                # real profile, launch flags, extensions, canvas/WebGL/audio
                # spoofing, etc.  Connecting over CDP keeps that environment
                # intact instead of starting a detectable plain Chrome.
                b = p.chromium.connect_over_cdp(self.cdp_endpoint)
                self.connected_over_cdp = True
                print(f"[Browser] connected over CDP: {self.cdp_endpoint}")
                return p, b

            if self.use_cloakbrowser:
                try:
                    p.stop()
                except Exception:
                    pass
                try:
                    import cloakbrowser
                except Exception as exc:
                    print(f"[Browser] cloakbrowser import failed: {exc!r}")
                    return False, False
                try:
                    version = getattr(cloakbrowser, "__version__", "?")
                    print(f"[Browser] launching CloakBrowser {version}")
                    # cloakbrowser 0.3.x occasionally mis-detects
                    # platform.machine() on this Windows host as an empty /
                    # punctuation value when it performs its own binary lookup,
                    # which returns (False, False) and makes the outer probe
                    # continue with a bogus browser object.  The runtime config
                    # already pins the known-good Cloak Chromium executable, so
                    # expose it through CLOAKBROWSER_BINARY_PATH and bypass the
                    # package's flaky platform auto-detection without changing
                    # the browser/profile/fingerprint path.
                    cloak_binary = self.browser_path if (self.browser_path and os.path.exists(self.browser_path)) else ""
                    if not cloak_binary:
                        try:
                            from pathlib import Path
                            candidates = []
                            home = Path.home()
                            for pattern in (
                                ".cloakbrowser/chromium-*/chrome.exe",
                                ".cache/cloakbrowser/chrome/**/chrome.exe",
                            ):
                                candidates.extend(home.glob(pattern))
                            candidates = [p for p in candidates if p.exists()]
                            if candidates:
                                cloak_binary = str(max(candidates, key=lambda p: p.stat().st_mtime))
                        except Exception:
                            cloak_binary = ""
                    if cloak_binary:
                        os.environ["CLOAKBROWSER_BINARY_PATH"] = cloak_binary
                    cloak_args = list(self.cloakbrowser_options.get("args", []))
                    fingerprint = self.cloakbrowser_options.get("fingerprint")
                    if fingerprint and not any(str(a).startswith("--fingerprint=") for a in cloak_args):
                        cloak_args.append(f"--fingerprint={fingerprint}")
                    platform = self.cloakbrowser_options.get("platform")
                    if platform and not any(str(a).startswith("--fingerprint-platform=") for a in cloak_args):
                        cloak_args.append(f"--fingerprint-platform={platform}")
                    launch_options = dict(self.context_options or {})
                    # CloakBrowser sets locale/timezone through stealth binary
                    # flags, so passing the same context options is okay; its
                    # wrapper accepts timezone_id as an alias too.
                    common = {
                        "headless": bool(self.cloakbrowser_options.get("headless", False)),
                        "proxy": self.proxy or None,
                        "geoip": bool(self.cloakbrowser_options.get("geoip", False)),
                        "humanize": bool(self.cloakbrowser_options.get("humanize", True)),
                        "human_preset": self.cloakbrowser_options.get("human_preset", "default"),
                        "args": cloak_args,
                    }
                    backend = self.cloakbrowser_options.get("backend")
                    if backend:
                        common["backend"] = backend
                    if self.user_data_dir:
                        os.makedirs(self.user_data_dir, exist_ok=True)
                        b = cloakbrowser.launch_persistent_context(
                            self.user_data_dir,
                            **common,
                            **launch_options,
                        )
                    else:
                        b = cloakbrowser.launch(**common)
                    return _NoopPlaywright(), b
                except Exception as exc:
                    print(f"[Browser] CloakBrowser launch failed: {exc!r}")
                    return False, False

            proxy_settings = {
                "server": self.proxy,
                "bypass": "localhost",
            } if self.proxy else None

            launch_kwargs = {
                "headless": self.headless,
                "args": [
                    '--lang=zh-CN',
                    '--disable-blink-features=AutomationControlled',
                    *self.extra_args,
                ],
                "proxy": proxy_settings,
            }
            if self.browser_path:
                launch_kwargs["executable_path"] = self.browser_path

            if self.user_data_dir:
                os.makedirs(self.user_data_dir, exist_ok=True)
                b = p.chromium.launch_persistent_context(
                    self.user_data_dir,
                    **launch_kwargs,
                    **self.context_options
                )
            else:
                b = p.chromium.launch(**launch_kwargs)

            return p, b

        except Exception as e:
            print(f"启动浏览器失败: {e}")
            return False, False
        
    def handle_captcha(self, page):
        mode = self.captcha_options.get("mode", "hold")
        if mode == "legacy_accessibility":
            return self.handle_captcha_legacy_accessibility(page)
        return self.handle_captcha_hold(page)

    def _captcha_finished_or_blocked(self, page):
        if page.get_by_text('账户创建已被阻止').count() or page.get_by_text('一些异常活动').count():
            print("[Error: Rate limit] - 长按验证后进入异常活动/阻断页。")
            return "blocked"

        # hsprotect 会在按压失败后保持 iframe，并显示“请再试一次”。
        # 主 frame 有时搜不到嵌套 about:blank 里的文本，所以遍历 frame。
        retry_markers = (
            '请再试一次',
            '請再試一次',
            'Please try again',
            'Try again',
            'もう一度',
            'やり直',
            'reintenta',
            'réessay',
        )
        try:
            for frame in page.frames:
                try:
                    for marker in retry_markers:
                        try:
                            if frame.get_by_text(marker).count() > 0:
                                return "retry"
                        except Exception:
                            continue
                    try:
                        text = frame.locator("body").inner_text(timeout=350)
                    except Exception:
                        text = ""
                    if text and any(marker.lower() in text.lower() for marker in retry_markers):
                        return "retry"
                except Exception:
                    continue
        except Exception:
            pass

        try:
            challenge_selectors = [
                'iframe[src*="iframe.hsprotect.net"][src*="ch_ctx=1"]',
                'iframe[data-testid="humanCaptchaIframe"]',
                'iframe[title="验证质询"]',
                'iframe[title*="Human" i]',
                'iframe[title*="captcha" i]',
                'iframe[title*="人間"]',
                'iframe[title*="検証"]',
                'iframe[title*="驗證"]',
                'iframe[title*="验证"]',
            ]
            for selector in challenge_selectors:
                try:
                    if page.locator(selector).count() > 0:
                        return None
                except Exception:
                    continue
            return "finished"
        except Exception:
            return "finished"

        return None

    def _viewport_bounds(self, page):
        try:
            size = page.viewport_size or {}
            width = int(size.get("width") or 0)
            height = int(size.get("height") or 0)
        except Exception:
            width = height = 0
        if width <= 0 or height <= 0:
            try:
                size = page.evaluate("""() => ({width: window.innerWidth, height: window.innerHeight})""")
                width = int(size.get("width") or 1365)
                height = int(size.get("height") or 768)
            except Exception:
                width, height = 1365, 768
        return 0, max(1, width - 1), 0, max(1, height - 1)

    @staticmethod
    def _clamp_point(x, y, min_x, max_x, min_y, max_y):
        return min(max(float(x), min_x), max_x), min(max(float(y), min_y), max_y)

    @staticmethod
    def _lerp(a, b, t):
        return a + (b - a) * t

    def _line_path(self, start, end, steps):
        return [
            (
                self._lerp(start[0], end[0], i / float(steps)),
                self._lerp(start[1], end[1], i / float(steps)),
            )
            for i in range(steps + 1)
        ]

    def _bezier_q(self, p0, p1, p2, t):
        s = 1 - t
        return (
            s * s * p0[0] + 2 * s * t * p1[0] + t * t * p2[0],
            s * s * p0[1] + 2 * s * t * p1[1] + t * t * p2[1],
        )

    def _arc_path(self, start, end, steps):
        dx = end[0] - start[0]
        dy = end[1] - start[1]
        dist = math.hypot(dx, dy) or 1.0
        nx, ny = -dy / dist, dx / dist
        mx, my = (start[0] + end[0]) / 2.0, (start[1] + end[1]) / 2.0
        ctrl = (
            mx + nx * dist * random.uniform(0.18, 0.55) * random.choice([-1, 1]),
            my + ny * dist * random.uniform(0.18, 0.55) * random.choice([-1, 1]),
        )
        return [self._bezier_q(start, ctrl, end, i / float(steps)) for i in range(steps + 1)]

    def _apply_jitter(self, path, max_norm=2.5, max_tan=1.2):
        if len(path) < 3:
            return path
        result = [path[0]]
        for i in range(1, len(path) - 1):
            px, py = path[i]
            dx = path[i + 1][0] - path[i - 1][0]
            dy = path[i + 1][1] - path[i - 1][1]
            dist = math.hypot(dx, dy) or 1.0
            # 法向 + 切向微扰，避免机械直线；首尾保持精准。
            nx, ny = -dy / dist, dx / dist
            tx, ty = dx / dist, dy / dist
            envelope = math.sin(math.pi * i / (len(path) - 1))
            jn = random.uniform(-max_norm, max_norm) * envelope
            jt = random.uniform(-max_tan, max_tan) * envelope
            result.append((px + nx * jn + tx * jt, py + ny * jn + ty * jt))
        result.append(path[-1])
        return result

    def _build_bezier_path(self, start, end, style=None):
        dist = math.hypot(end[0] - start[0], end[1] - start[1]) or 1.0
        steps = int(max(8, min(56, round(dist / random.uniform(9.0, 18.0)))))

        if style is None:
            style = random.choices(
                ["line_then_arc", "arc", "line", "overshoot"],
                weights=[0.42, 0.30, 0.18, 0.10],
                k=1,
            )[0]

        if style == "line_then_arc" and dist > 120:
            ratio = random.uniform(0.42, 0.72)
            mid = (self._lerp(start[0], end[0], ratio), self._lerp(start[1], end[1], ratio))
            path = self._line_path(start, mid, max(3, int(steps * ratio)))[:-1]
            path += self._arc_path(mid, end, max(3, steps - int(steps * ratio)))
        elif style == "line":
            path = self._line_path(start, end, steps)
        elif style == "overshoot" and dist > 160:
            ox = end[0] + (end[0] - start[0]) / dist * random.uniform(10, 28)
            oy = end[1] + (end[1] - start[1]) / dist * random.uniform(6, 18)
            path = self._line_path(start, (ox, oy), max(4, int(steps * 0.65)))[:-1]
            path += self._arc_path((ox, oy), end, max(4, int(steps * 0.35)))
        else:
            path = self._arc_path(start, end, steps)

        return self._apply_jitter(
            path,
            max_norm=min(6.0, max(1.0, dist * 0.008)),
            max_tan=min(3.0, max(0.4, dist * 0.004)),
        )

    def _build_windmouse_path(self, start, end):
        # 移植自 ruyipage._units.actions 的 windmouse 思路：
        # 风力扰动 + 重力收敛，比纯贝塞尔更像手部微抖轨迹。
        sx, sy = start
        ex, ey = end
        path = []
        x, y = float(sx), float(sy)
        velocity_x = velocity_y = 0.0
        wind_x = wind_y = 0.0

        gravity = random.uniform(7.0, 10.0)
        wind = random.uniform(2.5, 4.2)
        max_step = random.uniform(10.0, 18.0)
        target_area = random.uniform(9.0, 14.0)
        damping = random.uniform(0.78, 0.88)
        close_damping = random.uniform(0.55, 0.72)

        for _ in range(600):
            dx, dy = ex - x, ey - y
            dist = math.hypot(dx, dy)
            if dist <= 1.0:
                break

            wind_mag = min(wind, dist)
            if dist >= target_area:
                wind_x = wind_x / math.sqrt(3) + random.uniform(-wind_mag, wind_mag) / math.sqrt(5)
                wind_y = wind_y / math.sqrt(3) + random.uniform(-wind_mag, wind_mag) / math.sqrt(5)
            else:
                wind_x *= close_damping
                wind_y *= close_damping
                max_step = max(3.0, max_step * 0.93)

            velocity_x += wind_x + gravity * dx / dist
            velocity_y += wind_y + gravity * dy / dist
            velocity_x *= damping
            velocity_y *= damping

            velocity_mag = math.hypot(velocity_x, velocity_y)
            if velocity_mag > max_step:
                scale = max_step / velocity_mag
                velocity_x *= scale
                velocity_y *= scale

            prev_x, prev_y = x, y
            x += velocity_x
            y += velocity_y
            if int(prev_x) != int(x) or int(prev_y) != int(y):
                path.append((x, y))

        if not path or int(path[-1][0]) != int(ex) or int(path[-1][1]) != int(ey):
            path.append((float(ex), float(ey)))
        return path

    def _human_move_to(self, page, x, y):
        min_x, max_x, min_y, max_y = self._viewport_bounds(page)
        x, y = self._clamp_point(x, y, min_x, max_x, min_y, max_y)

        if self._last_mouse_pos:
            start_x, start_y = self._last_mouse_pos
            # Repeated captcha attempts often reuse the same button position.
            # If we start the next "human" move from exactly the previous
            # release point, windmouse collapses to a 1-point path, which is a
            # clear retry-side anomaly in live traces.  Force a short re-approach
            # from outside the button when the cursor is already on/near target.
            if math.hypot(float(start_x) - float(x), float(start_y) - float(y)) < 40:
                start_x = x + random.choice([-1, 1]) * random.uniform(95, 175)
                start_y = y + random.uniform(-70, 70)
        else:
            # 首次进入验证码时没有可靠鼠标位置，从按钮附近外侧起步，
            # 避免在整个视口内“瞬移”一大段后再移动。
            start_x = x + random.uniform(-160, 160)
            start_y = y + random.uniform(-85, 85)
        start_x, start_y = self._clamp_point(start_x, start_y, min_x, max_x, min_y, max_y)

        algorithm = str(self.captcha_options.get("move_algorithm", "windmouse")).strip().lower()
        style = self.captcha_options.get("move_style")
        if algorithm not in ("windmouse", "bezier"):
            algorithm = "windmouse"

        path = (
            self._build_windmouse_path((start_x, start_y), (x, y))
            if algorithm == "windmouse"
            else self._build_bezier_path((start_x, start_y), (x, y), style=style)
        )
        if not path or int(path[0][0]) != int(start_x) or int(path[0][1]) != int(start_y):
            path.insert(0, (start_x, start_y))
        if len(path) < 18:
            # Live AdsPower traces show very short pre-press approach paths
            # (for example 6 points) correlate with hsprotect final=-1 even
            # when the actual hold duration and PX561 z are in the accepted
            # range.  Densify only the approach path (before mouse down), so it
            # does not distort the measured hold wall_ms.
            dense = []
            for idx in range(18):
                t = idx / 17
                px = start_x + (x - start_x) * t
                py = start_y + (y - start_y) * t
                if 0 < idx < 17:
                    px += random.uniform(-1.1, 1.1)
                    py += random.uniform(-0.8, 0.8)
                dense.append((px, py))
            path = dense

        print(f"[Captcha] - human move algorithm={algorithm}, points={len(path)}")
        for idx, (px, py) in enumerate(path):
            px, py = self._clamp_point(px, py, min_x, max_x, min_y, max_y)
            page.mouse.move(px, py)
            # 起步稍慢，靠近目标时放缓，模拟“瞄准按钮”的过程。
            if idx < 3:
                delay = random.randint(24, 55)
            elif idx > len(path) * 0.78:
                delay = random.randint(18, 42)
            else:
                delay = random.randint(7, 22)
            page.wait_for_timeout(delay)

        # 落点前后做轻微悬停修正，移植 ruyipage human_move 的 hover 微调思想。
        for _ in range(random.randint(2, 4)):
            hx, hy = self._clamp_point(
                x + random.uniform(-2.2, 2.2),
                y + random.uniform(-1.4, 1.4),
                min_x,
                max_x,
                min_y,
                max_y,
            )
            page.mouse.move(hx, hy)
            page.wait_for_timeout(random.randint(24, 58))

        page.mouse.move(x, y)
        self._last_mouse_pos = (x, y)

    def _locate_hold_button(self, page):
        locate_started = time.time()
        # Most robust path: enumerate actual Frame objects. hsprotect injects
        # the hold button into nested about:blank frames, and frame titles /
        # styles vary across runs.
        button_selectors = [
            'div[role="button"]',
            '[role="button"]',
            'button',
            'input[type="button"]',
            'a[role="button"]',
            'text="按住"',
            'text=按住',
        ]
        hold_text_markers = (
            "按住",
            "长按",
            "按下",
            "Press",
            "press",
            "Hold",
            "hold",
        )
        try:
            for frame_index, frame in enumerate(page.frames):
                try:
                    frame_url = str(getattr(frame, "url", "") or "")
                    # The signup host can have many utility frames.  Querying
                    # every selector in every frame with text timeouts made the
                    # no-button/no-result0 path block for minutes.  hsprotect
                    # renders the hold control only in its own/about:blank
                    # frames, so keep this pass scoped and let the cheap layout /
                    # visible-iframe fallbacks handle the rest.
                    if frame_url and frame_url != "about:blank" and "hsprotect.net" not in frame_url:
                        continue
                    for button_selector in button_selectors:
                        if time.time() - locate_started > 2.2:
                            raise TimeoutError("fast frame scan budget exhausted")
                        loc = frame.locator(button_selector)
                        count = min(loc.count(), 5)
                        for idx in range(count):
                            target = loc.nth(idx)
                            try:
                                text = target.inner_text(timeout=120)
                            except Exception:
                                try:
                                    text = target.input_value(timeout=120)
                                except Exception:
                                    text = ""
                            try:
                                box = target.bounding_box(timeout=250)
                            except Exception:
                                box = None
                            if box and box.get("width", 0) > 20 and box.get("height", 0) > 10:
                                if button_selector.startswith("text=") and (
                                    "长按该按钮" in text
                                    or "the button" in text
                                    or "button." in text
                                ):
                                    continue
                                # On the current zh-CN challenge the clickable
                                # element is labelled "按住".  Some variants
                                # expose only a generic role/button inside the
                                # hsprotect/about:blank challenge frame, so keep
                                # that older fallback but accept real <button>
                                # and text-backed locators too.
                                if (
                                    any(marker in text for marker in hold_text_markers)
                                    or frame.url == "about:blank"
                                    or "iframe.hsprotect.net" in (frame.url or "")
                                ):
                                    print(
                                        f"[Captcha] - located hold button via frame[{frame_index}] "
                                        f"selector={button_selector!r} url={frame.url} text={text!r} box={box}"
                                    )
                                    return target, box
                except Exception:
                    continue
        except Exception:
            pass

        outer_selectors = [
            'iframe[title="验证质询"]',
            'iframe[title*="验证"]',
            'iframe[title*="楠岃瘉"]',
            'iframe[data-testid="humanCaptchaIframe"]',
            'iframe[src*="iframe.hsprotect.net"][src*="ch_ctx=1"]',
            'iframe[src*="iframe.hsprotect.net"]',
        ]
        inner_selectors = [
            'iframe[title="人工验证挑战"]',
            'iframe[title*="人工"]',
            'iframe[title*="浜哄伐"]',
            'iframe[style*="display: block"]',
            'iframe',
        ]

        for outer_selector in outer_selectors:
            if time.time() - locate_started > 4.0:
                break
            try:
                outer = page.frame_locator(outer_selector)

                # New hsprotect hold challenge renders the actual button inside
                # a nested about:blank iframe. Target the div role=button, not
                # the accessibility anchor.
                for inner_selector in inner_selectors:
                    if time.time() - locate_started > 4.0:
                        break
                    try:
                        inner = outer.frame_locator(inner_selector)
                        for button_selector in button_selectors + ['#oRMGBPQHbgupUji']:
                            if time.time() - locate_started > 4.0:
                                break
                            loc = inner.locator(button_selector)
                            if loc.count() > 0:
                                target = loc.first() if callable(getattr(loc, "first", None)) else loc.first
                                target.wait_for(state="visible", timeout=400)
                                box = target.bounding_box(timeout=250)
                                if box and box.get("width", 0) > 20 and box.get("height", 0) > 10:
                                    return target, box
                    except Exception:
                        continue

                # Fallback for variants that put the button directly in the
                # outer iframe.
                for button_selector in button_selectors + ['#oRMGBPQHbgupUji']:
                    if time.time() - locate_started > 4.0:
                        break
                    try:
                        loc = outer.locator(button_selector)
                        if loc.count() > 0:
                            target = loc.first() if callable(getattr(loc, "first", None)) else loc.first
                            target.wait_for(state="visible", timeout=400)
                            box = target.bounding_box(timeout=250)
                            if box and box.get("width", 0) > 20 and box.get("height", 0) > 10:
                                return target, box
                    except Exception:
                        continue
            except Exception:
                continue

        # Layout fallback for the current hsprotect zh-CN card.  Sometimes the
        # nested challenge frame is visible and receiving mouse events, but its
        # role/button node is not queryable through Patchright before the locate
        # deadline.  If the top page exposes the instruction text, derive the
        # real pill button rectangle from that text instead of clicking the
        # whole iframe/grey area.
        if self.captcha_options.get("allow_layout_hold_fallback", True) is not False:
            for instruction_selector in [
                'text="长按该按钮。"',
                'text=长按该按钮',
                'text="Press and hold"',
                'text=Press and hold',
            ]:
                try:
                    root = page.locator(instruction_selector)
                    if root.count() <= 0:
                        continue
                    loc = root.first() if callable(getattr(root, "first", None)) else root.first
                    box = loc.bounding_box(timeout=250)
                    if not box or box.get("width", 0) < 20 or box.get("height", 0) < 10:
                        continue
                    cx = box["x"] + box["width"] / 2
                    target_box = {
                        "x": cx + 24 - 112.5,
                        "y": box["y"] + 52,
                        "width": 225,
                        "height": 40,
                        "_px_source": "layout_instruction",
                    }
                    try:
                        viewport = page.viewport_size or {}
                        vw = float(viewport.get("width") or 0)
                        vh = float(viewport.get("height") or 0)
                        if vw > 0:
                            target_box["x"] = max(0, min(target_box["x"], vw - target_box["width"]))
                        if vh > 0:
                            target_box["y"] = max(0, min(target_box["y"], vh - target_box["height"]))
                    except Exception:
                        pass
                    print(f"[Captcha] - layout hold target via instruction {instruction_selector}: {target_box}")
                    return loc, target_box
                except Exception:
                    continue

        # Last-resort layout fallback for the fixed desktop viewport used by
        # this CTF profile.  It is gated by the challenge text so it does not
        # fire on unrelated pages.
        if self.captcha_options.get("allow_layout_hold_fallback", True) is not False:
            try:
                body = page.locator("body").inner_text(timeout=600)
            except Exception:
                body = ""
            if "长按" in body or "闀挎寜" in body or "Press and hold" in body:
                try:
                    viewport = page.viewport_size or {}
                    vw = float(viewport.get("width") or 1365)
                    vh = float(viewport.get("height") or 768)
                except Exception:
                    vw, vh = 1365.0, 768.0
                target_box = {
                    "x": max(0, min(vw * 0.435, vw - 225)),
                    "y": max(0, min(vh * 0.688, vh - 40)),
                    "width": 225,
                    "height": 40,
                    "_px_source": "layout_body",
                }
                print(f"[Captcha] - layout hold target via challenge body text: {target_box}")
                return page.locator("body"), target_box

        # Final fallback: in some runs hsprotect finishes bootstrapping after
        # the parent page already renders the visible grey hold area, but the
        # nested role=button is not queryable yet. Absolute mouse events inside
        # the visible iframe still reach the challenge document, so use a
        # conservative sub-rectangle of the iframe as the hold target.
        if self.captcha_options.get("allow_visible_iframe_fallback", True) is False:
            return None, None
        for iframe_selector in [
            'iframe[title="验证质询"]',
            'iframe[title*="验证"]',
            'iframe[title*="楠岃瘉"]',
            'iframe[data-testid="humanCaptchaIframe"]',
            'iframe[src*="iframe.hsprotect.net"][src*="ch_ctx=1"]',
            'iframe[src*="iframe.hsprotect.net"]',
        ]:
            try:
                root = page.locator(iframe_selector)
                loc = root.first() if callable(getattr(root, "first", None)) else root.first
                if loc.count() <= 0:
                    continue
                box = loc.bounding_box(timeout=250)
                if box and box.get("width", 0) > 80 and box.get("height", 0) > 35:
                    target_box = {
                        "x": box["x"] + box["width"] * 0.16,
                        "y": box["y"] + max(4, box["height"] * 0.12),
                        "width": box["width"] * 0.68,
                        "height": min(46, box["height"] * 0.62),
                        "_px_source": "visible_iframe",
                    }
                    print(f"[Captcha] - fallback hold target via visible iframe {iframe_selector}: {target_box}")
                    return loc, target_box
            except Exception:
                continue
        return None, None

    def handle_captcha_hold(self, page):
        hold_min_ms = int(self.captcha_options.get("hold_min_ms", 5200))
        hold_max_ms = int(self.captcha_options.get("hold_max_ms", 8800))
        post_wait_ms = int(self.captcha_options.get("post_wait_ms", 12000))
        retries = int(self.captcha_options.get("hold_retries", self.max_captcha_retries + 1))
        locate_timeout_ms = int(self.captcha_options.get("locate_timeout_ms", 22000))

        for attempt in range(retries):
            deadline = time.time() + max(1000, locate_timeout_ms) / 1000
            target, box = None, None
            while time.time() < deadline:
                target, box = self._locate_hold_button(page)
                if box:
                    break
                state = self._captcha_finished_or_blocked(page)
                if state == "finished":
                    return True
                if state == "blocked":
                    return False
                page.wait_for_timeout(random.randint(350, 700))

            if not box:
                print(f"[Captcha] - unable to locate hold button after {locate_timeout_ms}ms")
                state = self._captcha_finished_or_blocked(page)
                if state == "finished":
                    return True
                return False

            x = box['x'] + box['width'] / 2 + random.uniform(-box['width'] * 0.18, box['width'] * 0.18)
            y = box['y'] + box['height'] / 2 + random.uniform(-box['height'] * 0.20, box['height'] * 0.20)

            print(f"[Captcha] - hold attempt {attempt + 1}/{retries}, target=({x:.1f},{y:.1f}), box={box}")

            try:
                self._human_move_to(page, x, y)
                page.wait_for_timeout(random.randint(120, 380))
                page.mouse.down()

                hold_target_ms = random.randint(min(hold_min_ms, hold_max_ms), max(hold_min_ms, hold_max_ms))
                print(f"[Captcha] - holding for {hold_target_ms}ms")
                started = time.time()
                released = False
                jitter_probability = float(self.captcha_options.get("hold_jitter_probability", 0.14))
                jitter_x = float(self.captcha_options.get("hold_jitter_x", 0.8))
                jitter_y = float(self.captcha_options.get("hold_jitter_y", 0.6))

                while (time.time() - started) * 1000 < hold_target_ms:
                    page.wait_for_timeout(random.randint(140, 260))
                    # Keep a very small jitter inside the button. Real manual
                    # pressing is not pixel-perfect but should not leave target.
                    if random.random() < jitter_probability:
                        page.mouse.move(
                            x + random.uniform(-jitter_x, jitter_x),
                            y + random.uniform(-jitter_y, jitter_y),
                        )

                    # If challenge disappears after enough hold time, release.
                    if (time.time() - started) * 1000 > 1800:
                        state = self._captcha_finished_or_blocked(page)
                        if state == "blocked":
                            page.mouse.up()
                            released = True
                            return False
                        if state == "finished":
                            page.mouse.up()
                            released = True
                            page.wait_for_timeout(800)
                            return True
                        if state == "retry":
                            page.mouse.up()
                            released = True
                            print("[Captcha] - challenge requested retry while holding")
                            break

                if not released:
                    page.mouse.up()

                page.wait_for_timeout(random.randint(600, 1400))

                # Give the signup page time to consume the proof and remove the
                # challenge iframe.
                deadline = time.time() + post_wait_ms / 1000
                while time.time() < deadline:
                    state = self._captcha_finished_or_blocked(page)
                    if state == "blocked":
                        return False
                    if state == "finished":
                        return True
                    if state == "retry":
                        print("[Captcha] - challenge requested retry after release")
                        break
                    page.wait_for_timeout(350)

            except Exception as e:
                try:
                    page.mouse.up()
                except Exception:
                    pass
                print(f"[Captcha] - hold attempt error: {e}")
                page.wait_for_timeout(1000)

        return False

    def handle_captcha_legacy_accessibility(self, page):

        frame1 = page.frame_locator('iframe[title="验证质询"]')
        frame2 = frame1.frame_locator('iframe[style*="display: block"]')


        for _ in range(0, self.max_captcha_retries + 1):

            page.wait_for_timeout(200)
            loc = frame2.locator('[aria-label="可访问性挑战"]')
            box = loc.bounding_box(timeout=250)
            x = box['x'] + box['width'] / 2 + random.randint(-10, 10)
            y = box['y'] + box['height'] / 2 + random.randint(-10, 10)
            page.mouse.click(x, y)

            loc2 = frame2.locator('[aria-label="再次按下"]')
            box2 = loc2.bounding_box(timeout=250)
            x = box2['x'] + box2['width'] / 2 + random.randint(-20, 20)
            y = box2['y'] + box2['height'] / 2 + random.randint(-13, 13)
            page.mouse.click(x, y)

            try:

                page.locator('.draw').wait_for(state="detached")
                try:

                    # 简单的认为加载8秒后成功，暂不考虑请求.
                    page.locator('[role="status"][aria-label="正在加载..."]').wait_for(timeout=5000)
                    page.wait_for_timeout(8000)
                    if page.get_by_text('一些异常活动').count() or page.get_by_text('此站点正在维护，暂时无法使用，请稍后重试。').count() > 0:
                        print("[Error: Rate limit] - 正常通过验证码，但当前IP注册频率过快。")
                        return False
                    elif frame2.locator('[aria-label="可访问性挑战"]').count() > 0:
                        continue
                    break

                except:

                    if page.get_by_text('取消').count() > 0:
                        break
                    frame1.get_by_text("请再试一次").wait_for(timeout=15000)
                    continue

            except:
                if page.get_by_text('取消').count() > 0:
                     break
                return False
        else: 
            return False

        return True

    def get_thread_page(self):
        browser_or_context = self.get_thread_browser()
        if self.connected_over_cdp:
            try:
                contexts = list(browser_or_context.contexts)
            except Exception:
                contexts = []
            if contexts:
                return contexts[0].new_page()
            context = browser_or_context.new_context(**self.context_options)
            return context.new_page()
        if self.user_data_dir:
            return browser_or_context.new_page()

        context = browser_or_context.new_context(**self.context_options)
        return context.new_page()

    def clean_up(self, page=None, type="all_browser"):
        if type == "done_browser" and page:
            try:
                if self.connected_over_cdp:
                    # Do not close the operator's CloakBrowser profile tab unless
                    # the caller closes it manually.
                    pass
                elif self.user_data_dir:
                    page.close()
                else:
                    context = page.context
                    context.close()
            except Exception as exc:
                # Driver disconnects are common after a timed-out/riskblocked
                # probe.  Cleanup should not turn an already-classified run into
                # a generic crash.
                print(f"[Browser] cleanup ignored: {exc!r}")

        elif type == "all_browser":
            for p, b in self.active_resources:
                if not (self.connected_over_cdp and self.cdp_keep_open):
                    try:
                        b.close()
                    except Exception: pass
                try:
                    p.stop()
                except Exception: pass

    
