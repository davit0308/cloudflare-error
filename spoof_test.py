"""
spoof_test.py - Gia lap fingerprint de KIEM THU honeypot cua chinh ban.

Cai dat:
    pip install playwright
    playwright install chromium

Chay:
    python spoof_test.py                         # test len http://127.0.0.1:8084/
    python spoof_test.py https://xxx.trycloudflare.com/

Sua PROFILE ben duoi de tao cac ho so khac nhau. Muon test lop phat hien
mau thuan ch, co tinh de UA mobile + may that la desktop -> honeypot phai bat duoc.
"""
import sys
import json
from playwright.sync_api import sync_playwright

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8084/"

# ===== PROXY (de doi IP / geo / CF-Country). None = dung mang that cua may. =====
# Vi du:
#   PROXY = {"server": "http://host:port"}
#   PROXY = {"server": "http://host:port", "username": "u", "password": "p"}
#   PROXY = {"server": "socks5://127.0.0.1:9050"}   # Tor
PROXY = None

# ===== HO SO GIA (chinh tuy y) =====
PROFILE = {
    # --- cac truong Playwright ho tro san qua new_context ---
    "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                  "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "locale": "en-US",
    "timezone_id": "America/New_York",
    "viewport": {"width": 390, "height": 844},
    "device_scale_factor": 3,
    "is_mobile": True,
    "has_touch": True,
    "screen": {"width": 390, "height": 844},

    # --- cac truong phai override bang JS (add_init_script) ---
    "platform": "iPhone",
    "vendor": "Apple Computer, Inc.",
    "languages": ["en-US", "en"],
    "hardware_concurrency": 6,
    "device_memory": 4,
    "max_touch_points": 5,
    "color_depth": 32,
    "webgl_vendor": "Apple Inc.",
    "webgl_renderer": "Apple GPU",

    # --- cong tac tuy chon ---
    "spoof_math": False,  # True = ghi de Math.* de doi Math FP (bat thuong, de bi coi la dau hieu la)
}

INIT_JS = """
(profile => {
  const def = (obj, prop, val) => {
    try { Object.defineProperty(obj, prop, { get: () => val, configurable: true }); } catch (e) {}
  };
  def(navigator, 'platform', profile.platform);
  def(navigator, 'vendor', profile.vendor);
  def(navigator, 'languages', profile.languages);
  def(navigator, 'hardwareConcurrency', profile.hardware_concurrency);
  def(navigator, 'deviceMemory', profile.device_memory);
  def(navigator, 'maxTouchPoints', profile.max_touch_points);
  def(screen, 'colorDepth', profile.color_depth);
  def(screen, 'pixelDepth', profile.color_depth);

  // WebGL vendor/renderer (che ca duong debug_renderer_info)
  const patch = (proto) => {
    const orig = proto.getParameter;
    proto.getParameter = function (p) {
      if (p === 37445) return profile.webgl_vendor;    // UNMASKED_VENDOR_WEBGL
      if (p === 37446) return profile.webgl_renderer;  // UNMASKED_RENDERER_WEBGL
      return orig.call(this, p);
    };
  };
  if (window.WebGLRenderingContext)  patch(WebGLRenderingContext.prototype);
  if (window.WebGL2RenderingContext) patch(WebGL2RenderingContext.prototype);

  // Canvas: them nhieu 1px de hash doi khac
  const toURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function (...a) {
    const ctx = this.getContext('2d');
    if (ctx) { ctx.fillStyle = 'rgba(0,0,0,0.01)'; ctx.fillRect(0, 0, 1, 1); }
    return toURL.apply(this, a);
  };

  // Audio: bom nhieu NHAN vao getChannelData -> Audio FP doi moi lan chay.
  // Dung nhieu nhan ~1e-4 (kieu "farbling" cua Brave); nhieu cong qua nho
  // (1e-7) se bi Float32 lam tron mat -> hash khong doi.
  const origGCD = AudioBuffer.prototype.getChannelData;
  AudioBuffer.prototype.getChannelData = function (...a) {
    const data = origGCD.apply(this, a);
    for (let i = 0; i < data.length; i++) {
      data[i] = data[i] * (1 + (Math.random() - 0.5) * 2e-4);
    }
    return data;
  };

  // Math FP (tuy chon): ghi de cac ham Math.* de doi fingerprint
  if (profile.spoof_math) {
    const jitter = () => 1 + (Math.random() - 0.5) * 1e-12;
    ['acos', 'asin', 'cos', 'sin', 'tan', 'sinh', 'cosh', 'log', 'sqrt', 'exp'].forEach((fn) => {
      const orig = Math[fn];
      Math[fn] = (x) => orig(x) * jitter();
    });
  }
})(%s);
""" % json.dumps(PROFILE)


def main():
    with sync_playwright() as p:
        launch_kwargs = {"headless": False}  # headless=True neu chay ngam
        if PROXY:
            launch_kwargs["proxy"] = PROXY
            print(f"[*] Dung proxy: {PROXY['server']}")
        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context(
            user_agent=PROFILE["user_agent"],
            locale=PROFILE["locale"],
            timezone_id=PROFILE["timezone_id"],
            viewport=PROFILE["viewport"],
            device_scale_factor=PROFILE["device_scale_factor"],
            is_mobile=PROFILE["is_mobile"],
            has_touch=PROFILE["has_touch"],
            screen=PROFILE["screen"],
        )
        context.add_init_script(INIT_JS)
        page = context.new_page()
        print(f"[*] Truy cap {TARGET} voi ho so gia...")
        page.goto(TARGET, wait_until="networkidle")
        page.wait_for_timeout(4000)  # cho JS gui fingerprint ve /__client_info
        print("[*] Xong. Kiem tra tin nhan Telegram.")
        browser.close()


if __name__ == "__main__":
    main()
