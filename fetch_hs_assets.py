import argparse
from pathlib import Path

from patchright.sync_api import sync_playwright


DEFAULT_URLS = [
    "https://client.hsprotect.net/PXzC5j78di/main.min.js",
    "https://captcha.hsprotect.net/PXzC5j78di/captcha.js?a=c&m=0&u=1d37eb30-6c30-11f1-a594-25906eb1eb48&v=1b05f45e-6c26-11f1-aeff-9aecc0d219f7",
]


def main():
    parser = argparse.ArgumentParser(description="Fetch hsprotect JS assets through browser network stack")
    parser.add_argument("--out-dir", default=str(Path("Results") / "protocol"))
    parser.add_argument("--browser-path", default=r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    parser.add_argument("urls", nargs="*", default=DEFAULT_URLS)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, executable_path=args.browser_path)
        page = browser.new_page()
        for url in args.urls:
            print(f"[fetch] {url}")
            resp = page.goto(url, wait_until="domcontentloaded", timeout=60000)
            status = resp.status if resp else "?"
            text = page.locator("body").inner_text(timeout=30000)
            name = "captcha.js" if "captcha.hsprotect.net" in url else "main.min.js"
            path = out_dir / name
            path.write_text(text, encoding="utf-8")
            print(f"[save] {path} status={status} chars={len(text)}")
        browser.close()


if __name__ == "__main__":
    raise SystemExit(main())
