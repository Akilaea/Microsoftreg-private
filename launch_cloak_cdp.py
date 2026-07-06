import argparse
import os
import secrets
import subprocess
import sys
import time
import urllib.request
import cloakbrowser

parser = argparse.ArgumentParser()
parser.add_argument('--url', default='about:blank')
parser.add_argument('--profile-name', default=None)
parser.add_argument('--profile-dir', default=None)
parser.add_argument('--proxy', default='')
parser.add_argument('--port', type=int, default=19222)
parser.add_argument('--timezone', default='Asia/Shanghai')
parser.add_argument('--locale', default='zh-CN')
args_ns = parser.parse_args()

binary = cloakbrowser.binary_info()
if not binary.get('installed'):
    cloakbrowser.ensure_binary()
    binary = cloakbrowser.binary_info()
chrome_exe = binary['binary_path']

profile_name = args_ns.profile_name or ('manual_cdp_' + secrets.token_hex(4))
profile_dir = args_ns.profile_dir or os.path.join(os.getcwd(), 'profiles', profile_name)
os.makedirs(profile_dir, exist_ok=True)

cargs = cloakbrowser.build_args(
    stealth_args=True,
    extra_args=None,
    timezone=args_ns.timezone,
    locale=args_ns.locale,
    headless=False,
)
cargs += [
    f'--user-data-dir={profile_dir}',
    f'--remote-debugging-port={args_ns.port}',
    '--remote-allow-origins=*',
    '--no-first-run',
    '--no-default-browser-check',
]
if args_ns.proxy:
    cargs += [f'--proxy-server={args_ns.proxy}', '--proxy-bypass-list=<-loopback>']

cmd = [chrome_exe] + cargs + [args_ns.url]
print('chrome_exe=', chrome_exe)
print('profile=', profile_dir)
print('proxy=', args_ns.proxy)
print('cdp=', f'http://127.0.0.1:{args_ns.port}')
proc = subprocess.Popen(cmd)
print('pid=', proc.pid)
# best effort wait for CDP endpoint
for i in range(40):
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{args_ns.port}/json/version', timeout=0.5) as r:
            print('cdp_ready=', r.status)
            print(r.read().decode('utf-8', 'replace')[:500])
            break
    except Exception as e:
        if i == 39:
            print('cdp_not_ready=', repr(e))
        time.sleep(0.25)
