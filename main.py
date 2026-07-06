import os
import time
import argparse
import socket
import json
from datetime import datetime
from urllib.parse import urlparse
from get_token import get_access_token
from concurrent.futures import ThreadPoolExecutor
from utils import random_email, generate_strong_password
from controllers.patchright_controller import PatchrightController
from controllers.playwright_controller import PlaywrightController
from settings import load_config


def proxy_reachable(proxy_url, timeout=2):
    if not proxy_url:
        return True, "no proxy configured"

    parsed = urlparse(proxy_url)
    host = parsed.hostname
    port = parsed.port
    if not host:
        return False, f"invalid proxy url: {proxy_url}"
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"{host}:{port}"
    except OSError as exc:
        return False, f"{host}:{port} unreachable: {exc}"



# --- 不确定有无帮助 ---
# 0. 视窗大小
# 1. CDP 检测：wait_for_timeout --> time.sleep()
# 2. 使用 launch_persistent_context 
# 3. 避免短时间访问
# 4. 模拟真人轨迹

def normalize_email_arg(email_arg, email_suffix):
    if not email_arg:
        return None
    if "@" not in email_arg:
        return email_arg
    if not email_arg.endswith(email_suffix):
        raise ValueError(f"--email suffix must match config email_suffix: {email_suffix}")
    return email_arg[:-len(email_suffix)]


def process_single_flow(controller, email=None, password=None):
    page = None

    try:
        page = controller.get_thread_page()

        email = email or random_email()
        password = password or generate_strong_password()

        # 调用 controller 特定的注册方法
        result = controller.outlook_register(page, email, password)

        if result and not controller.enable_oauth2:
            return True
        elif not result:
            return False

        token_result = get_access_token(page, email)
        if token_result[0]:
            refresh_token, access_token, expire_at =  token_result
            with open(os.path.join(os.path.dirname(__file__), 'Results', 'outlook_token.txt'), 'a', encoding='utf-8') as f2:
                f2.write(f"{email}{controller.email_suffix}---{password}---{refresh_token}---{access_token}---{expire_at}\n") 
            print(f'[Success: TokenAuth] - {email}{controller.email_suffix}')
            return True
        else:
            return False

    except Exception as e:
        print(e)
        return False
    
    finally:

        controller.clean_up(page, "done_browser")

def run_concurrent_flows(controller, concurrent_flows=10, max_tasks=100, email=None, password=None):
    task_counter = 0
    succeeded_tasks = 0
    failed_tasks = 0

    with ThreadPoolExecutor(max_workers=concurrent_flows) as executor:
        running_futures = set()

        while task_counter < max_tasks or len(running_futures) > 0:
            done_futures = {f for f in running_futures if f.done()}
            for future in done_futures:
                try:
                    if future.result():
                        succeeded_tasks += 1
                    else:
                        failed_tasks += 1
                except Exception as e:
                    failed_tasks += 1
                    print(e)
                running_futures.remove(future)

            while len(running_futures) < concurrent_flows and task_counter < max_tasks:
                new_future = executor.submit(process_single_flow, controller, email, password)
                running_futures.add(new_future)
                task_counter += 1
                if max_tasks > 1 and task_counter % (max_tasks // 2) == 0:
                    print(f"已提交 {task_counter}/{max_tasks} 任务.")
                elif max_tasks == 1:
                    print(f"已提交 {task_counter}/{max_tasks} 任务.")

            time.sleep(0.5)

    print(f"\n[Result] - 共: {max_tasks}, 成功 {succeeded_tasks}, 失败 {failed_tasks}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Outlook registration flow tester")
    parser.add_argument("--config", default=os.environ.get("OUTLOOK_REGISTER_CONFIG", "config.json"))
    parser.add_argument("--max-tasks", type=int, default=None)
    parser.add_argument("--concurrent", type=int, default=None)
    parser.add_argument("--email", default=None, help="Optional fixed username or full address; only valid with one task.")
    parser.add_argument("--password", default=None, help="Optional fixed password; only valid with one task.")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--manual-captcha", action="store_true", help="Fill the form automatically, then wait for manual captcha solving.")
    parser.add_argument("--manual-captcha-wait-seconds", type=int, default=None)
    parser.add_argument("--manual-post-verify-wait-seconds", type=int, default=None)
    parser.add_argument("--cdp-endpoint", default=None, help="Connect to an already launched fingerprint browser over CDP.")
    parser.add_argument("--use-cloakbrowser", action="store_true", help="Launch via the installed cloakbrowser package instead of stock Chrome/Patchright.")
    parser.add_argument("--cloak-fingerprint", default=None, help="Optional fixed CloakBrowser fingerprint seed.")
    parser.add_argument("--cloak-human-preset", default="default", choices=["default", "careful"])
    args = parser.parse_args()

    os.environ["OUTLOOK_REGISTER_CONFIG"] = args.config
    data = load_config()
    runtime_config_modified = False
    if args.manual_captcha:
        data["manual_captcha"] = True
        runtime_config_modified = True
    if args.manual_captcha_wait_seconds is not None:
        data["manual_captcha_wait_seconds"] = int(args.manual_captcha_wait_seconds)
        runtime_config_modified = True
    if args.manual_post_verify_wait_seconds is not None:
        data["manual_post_verify_wait_seconds"] = int(args.manual_post_verify_wait_seconds)
        runtime_config_modified = True
    if args.cdp_endpoint:
        data.setdefault("patchright", {})["cdp_endpoint"] = args.cdp_endpoint
        data.setdefault("patchright", {})["cdp_keep_open"] = True
        runtime_config_modified = True
    if args.use_cloakbrowser:
        data.setdefault("patchright", {})["use_cloakbrowser"] = True
        data.setdefault("cloakbrowser", {})["humanize"] = True
        data.setdefault("cloakbrowser", {})["human_preset"] = args.cloak_human_preset
        if args.cloak_fingerprint:
            data.setdefault("cloakbrowser", {})["fingerprint"] = args.cloak_fingerprint
        runtime_config_modified = True
    if runtime_config_modified:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        runtime_config = f"config.ctf.runtime.main-manual.{stamp}.json"
        with open(runtime_config, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        os.environ["OUTLOOK_REGISTER_CONFIG"] = runtime_config
        args.config = runtime_config
        data = load_config()
        print(f"[Runtime] override config={runtime_config} manual={data.get('manual_captcha')} cdp={'yes' if data.get('patchright', {}).get('cdp_endpoint') else 'no'}")
    os.makedirs("Results", exist_ok=True)

    max_tasks = args.max_tasks if args.max_tasks is not None else data["max_tasks"]
    concurrent_flows = args.concurrent if args.concurrent is not None else data["concurrent_flows"]
    fixed_email = normalize_email_arg(args.email, data["email_suffix"])
    fixed_password = args.password
    if (fixed_email or fixed_password) and (max_tasks != 1 or concurrent_flows != 1):
        print("[Preflight] --email/--password can only be used with --max-tasks 1 --concurrent 1")
        raise SystemExit(2)

    if not args.skip_preflight:
        ok, detail = proxy_reachable(data.get("proxy"))
        if not ok:
            print(f"[Preflight] proxy check failed: {detail}")
            print("[Preflight] fix config proxy / start the internal proxy, or use --skip-preflight if your sandbox routes traffic transparently.")
            raise SystemExit(2)

    if data["choose_browser"] =="patchright":
        selected_controller = PatchrightController()
    elif data["choose_browser"] =="playwright":
        selected_controller = PlaywrightController()
    else:
        print("不支持的浏览器类型，填写patchright或者playwright")
  

    try:
        run_concurrent_flows(selected_controller, concurrent_flows, max_tasks, fixed_email, fixed_password)
    finally:
        selected_controller.clean_up(type="all_browser")
