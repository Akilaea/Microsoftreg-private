import argparse
import json
import os
import time
from datetime import datetime
from pathlib import Path
from patchright.sync_api import sync_playwright

KEYWORDS = [
    'outlook.live.com',
    'signup.live.com',
    'login.microsoftonline.com',
    'login.live.com',
    'account.live.com',
    'client.hip.live.com',
    'iframe.hsprotect.net',
    'captcha.hsprotect.net',
    'client.hsprotect.net',
    'collector-pxzc5j78di.hsprotect.net',
    'hsprotect.net',
    'fpt.live.com',
    'browser.events.data.microsoft.com',
]
BODY_KEYWORDS = [
    'collector-pxzc5j78di.hsprotect.net',
    'signup.live.com/API/CreateAccount',
    'signup.live.com/API/CheckAvailableSigninNames',
    'risk/verify',
    'risk/initialize',
    'api/v1.0/risk',
]


def now_iso():
    return datetime.now().isoformat()


def bounded(text, n=1000000):
    if text is None:
        return None
    if len(text) <= n:
        return text
    return text[:n] + f"\n<truncated {len(text)-n} chars>"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cdp-endpoint', default='http://127.0.0.1:19222')
    ap.add_argument('--timeout-seconds', type=int, default=360)
    ap.add_argument('--out', default='')
    args = ap.parse_args()

    out_dir = Path('Results') / 'network'
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_path = Path(args.out) if args.out else out_dir / f'{stamp}_manual_cdp_observer.jsonl'
    seen_pages = set()
    seen_contexts = set()
    create_200 = {'hit': False}
    risk_seen = {'passed': False, 'challenge': 0}

    def write(obj):
        with out_path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(obj, ensure_ascii=False, separators=(',', ':')) + '\n')

    def want(url):
        return any(k in (url or '') for k in KEYWORDS)

    def req_record(req):
        url = req.url
        if not want(url):
            return
        rec = {
            'ts': now_iso(),
            'event': 'request',
            'method': req.method,
            'url': url,
            'resource_type': req.resource_type,
        }
        try:
            rec['headers'] = dict(req.headers)
        except Exception:
            pass
        if req.method.upper() in ('POST', 'PUT', 'PATCH'):
            try:
                pd = req.post_data
                if pd is not None:
                    rec['post_data'] = bounded(pd)
            except Exception as e:
                rec['post_data_error'] = repr(e)[:200]
        write(rec)

    def resp_record(resp):
        url = resp.url
        if not want(url):
            return
        req = resp.request
        rec = {
            'ts': now_iso(),
            'event': 'response',
            'method': req.method,
            'url': url,
            'status': resp.status,
        }
        try:
            rec['headers'] = dict(resp.headers)
        except Exception:
            pass
        if any(k in url for k in BODY_KEYWORDS):
            try:
                rec['body'] = bounded(resp.text())
            except Exception as e:
                rec['body_error'] = repr(e)[:240]
        write(rec)
        if 'api/v1.0/risk/verify' in url and req.method.upper() == 'POST':
            body = str(rec.get('body') or '')
            err_code = ''
            inner_code = ''
            state = ''
            try:
                parsed = json.loads(body) if body else {}
                state = parsed.get('state') or ''
                err = parsed.get('error') or {}
                err_code = err.get('code') or ''
                inner_code = (err.get('innerError') or {}).get('code') or ''
            except Exception:
                state = ''
            if state or err_code or inner_code or rec.get('status'):
                print(
                    f'[Observer] risk/verify status={rec.get("status")} '
                    f'state={state or "-"} err={err_code or "-"} inner={inner_code or "-"}',
                    flush=True,
                )
                if state == 'riskChallengeRequired':
                    risk_seen['challenge'] += 1
                if state not in ('riskChallengeRequired', 'riskInitializationRequired'):
                    risk_seen['passed'] = True
                if inner_code == 'riskBlock':
                    risk_seen['passed'] = False
        if req.method.upper() == 'POST' and 'signup.live.com/API/CreateAccount' in url and int(resp.status or 0) == 200:
            create_200['hit'] = True
            print('[Observer] CreateAccount 200 captured', flush=True)

    def attach_page(page):
        ident = id(page)
        if ident in seen_pages:
            return
        seen_pages.add(ident)
        try:
            print('[Observer] attach page', page.url, flush=True)
        except Exception:
            print('[Observer] attach page <unknown>', flush=True)
        page.on('request', req_record)
        page.on('response', resp_record)

    print(f'[Observer] network log: {out_path.resolve()}', flush=True)
    p = sync_playwright().start()
    try:
        browser = p.chromium.connect_over_cdp(args.cdp_endpoint)
        def attach_contexts():
            for ctx in browser.contexts:
                ident = id(ctx)
                if ident not in seen_contexts:
                    seen_contexts.add(ident)
                    ctx.on('page', attach_page)
                for pg in ctx.pages:
                    attach_page(pg)

        attach_contexts()
        deadline = time.time() + max(1, args.timeout_seconds)
        while time.time() < deadline and not create_200['hit']:
            # attach any late pages/contexts
            attach_contexts()
            time.sleep(0.5)
        print(
            f'[Observer] done create_200={create_200["hit"]} '
            f'risk_passed_like={risk_seen["passed"]} '
            f'risk_challenge_count={risk_seen["challenge"]} '
            f'out={out_path.resolve()}',
            flush=True,
        )
        # do not close browser; CDP detach only
    finally:
        try:
            p.stop()
        except Exception:
            pass

if __name__ == '__main__':
    main()
