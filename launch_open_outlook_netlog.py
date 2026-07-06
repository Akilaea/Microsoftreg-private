import sys
import subprocess
import secrets
import pathlib
import datetime
import json
import cloakbrowser

binary = cloakbrowser.binary_info()
if not binary.get('installed'):
    print('CloakBrowser 内核未安装，正在下载...')
    cloakbrowser.ensure_binary()
    binary = cloakbrowser.binary_info()
chrome_exe = binary['binary_path']

args = cloakbrowser.build_args(
    stealth_args=True,
    extra_args=None,
    timezone='Asia/Shanghai',
    locale='zh-CN',
    headless=False,
)

if len(sys.argv) > 2:
    profile_name = sys.argv[2]
else:
    profile_name = 'netlog_' + secrets.token_hex(4)
user_data_dir = rf'C:\Users\wdnmd\ZCodeProject\profiles\{profile_name}'
args += [f'--user-data-dir={user_data_dir}']

target_url = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].startswith('http') else 'https://signup.live.com'

out_dir = pathlib.Path(r'C:\Users\wdnmd\Documents\outlook\OutlookRegister-main\OutlookRegister-repo\Results\netlog')
out_dir.mkdir(parents=True, exist_ok=True)
stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
netlog_path = out_dir / f'{stamp}_{profile_name}.netlog.json'
meta_path = out_dir / f'{stamp}_{profile_name}.meta.json'

# Low-pollution capture: no CDP, no Playwright, no proxy.  Only Chrome's own
# netlog file, so the browser remains otherwise equivalent to open_outlook.py.
args += [
    f'--log-net-log={netlog_path}',
    '--net-log-capture-mode=IncludeSensitive',
]

meta = {
    'created_at': stamp,
    'profile_name': profile_name,
    'user_data_dir': user_data_dir,
    'target_url': target_url,
    'netlog_path': str(netlog_path),
    'chrome_exe': chrome_exe,
    'binary_version': binary.get('version'),
}
meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding='utf-8')

print('=' * 60)
print('CloakBrowser 原脚本兼容 + Chrome netlog 低污染采样')
print(f"  内核版本 : {binary.get('version')}")
print(f'  Profile  : {profile_name}  ({user_data_dir})')
print('  指纹     : 随机（每次启动都不同）')
print('  时区     : Asia/Shanghai')
print('  语言     : zh-CN')
print(f'  打开页面 : {target_url}')
print(f'  NetLog   : {netlog_path}')
print('=' * 60)

proc = subprocess.Popen([chrome_exe] + args + [target_url])
print(f'浏览器进程 PID: {proc.pid}（已独立运行，本脚本可关闭）')
print(f'META={meta_path}')
print(f'NETLOG={netlog_path}')
