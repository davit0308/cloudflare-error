import os
import re
import time
import json
import hmac
import hashlib
import secrets
import threading
import html
import requests
from collections import defaultdict, deque
from dotenv import load_dotenv
from flask import Flask, request
from cloudflare_error_page import ErrorPageParams, render as render_cf_error_page

load_dotenv()

# =====================================================================
# CAU HINH (bat buoc doc tu bien moi truong / file .env - xem .env.example)
# =====================================================================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    print("[!] CANH BAO: thieu TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID trong .env - se khong gui duoc canh bao.")

# Khoa ky token phien. Neu khong dat trong .env, sinh ngau nhien moi lan
# khoi dong (token cu se mat hieu luc sau restart - chi anh huong scoring,
# khong lam mat du lieu da thu thap).
HONEYPOT_SECRET = os.getenv("HONEYPOT_SECRET") or secrets.token_hex(32)

# Duong dan "bay" an - xem ham build_honeytrap_link(). Doi gia tri nay
# truoc khi deploy that (dat trong .env, dung dat trong code/git).
HONEYTRAP_PATH = os.getenv("HONEYTRAP_PATH", "sys-panel-7f3a2c").strip("/")

# File log JSONL de luu lai toan bo fingerprint tho (phuc vu doi chieu/forensics
# sau nay), doc lap voi Telegram (Telegram co the mat/roi tin nhan).
LOG_FILE = os.getenv("LOG_FILE", "fingerprints.jsonl")

# Ten mien mac dinh khi khong doc duoc header Host
TARGET_DOMAIN = os.getenv("TARGET_DOMAIN", "tr4c3.me")

LISTEN_HOST = os.getenv("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8084"))

app = Flask(__name__)

# =====================================================================
# JAVASCRIPT FINGERPRINTING (client-side)
# Chi thu thap cac tin hieu IM LANG (khong bat popup xin quyen),
# roi POST JSON ve /__client_info de SERVER xu ly va gui Telegram.
# Da bo: GPS, Battery, Media Devices, WebRTC (codec + local IP),
#         IP-geo phia client (chuyen sang server-side).
# =====================================================================
FINGERPRINT_JS_TEMPLATE = r"""
<script>
(async function () {
  const HP_TOKEN = %(token)s;
  const safe = (fn) => { try { return fn(); } catch (e) { return 'N/A'; } };
  const safeAsync = async (fn) => { try { return await fn(); } catch (e) { return 'N/A'; } };

  const nav = navigator, scr = screen, ua = nav.userAgent;
  const archMatch = ua.match(/Win64|x64|WOW64|x86_64|AMD64|aarch64|arm64/i);

  const basic = {
    userAgent: ua,
    platform: nav.platform + ' (arch: ' + (archMatch ? archMatch[0] : '32-bit') + ')',
    vendor: nav.vendor || 'N/A',
    language: nav.language,
    languages: (nav.languages || []).join(', '),
    cookieEnabled: nav.cookieEnabled,
    doNotTrack: nav.doNotTrack || 'unset',
    onLine: nav.onLine,
    pdfViewerEnabled: safe(() => nav.pdfViewerEnabled),
    webdriver: safe(() => nav.webdriver === true),
  };

  const dpr = window.devicePixelRatio || 1;
  const display = {
    physical: Math.round(scr.width * dpr) + 'x' + Math.round(scr.height * dpr),
    css: scr.width + 'x' + scr.height,
    avail: scr.availWidth + 'x' + scr.availHeight,
    colorDepth: scr.colorDepth,
    pixelDepth: scr.pixelDepth,
    dpr: dpr,
    viewport: window.innerWidth + 'x' + window.innerHeight,
    outer: window.outerWidth + 'x' + window.outerHeight,
    orientation: safe(() => screen.orientation.type),
  };

  const off = new Date().getTimezoneOffset();
  const tz = {
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    offsetMin: off,
    locale: Intl.DateTimeFormat().resolvedOptions().locale,
    timestamp: new Date().toISOString(),
  };

  const hw = {
    cpuCores: nav.hardwareConcurrency || 'N/A',
    deviceMemoryGB: nav.deviceMemory || 'N/A',
    maxTouchPoints: nav.maxTouchPoints,
    isTouchDevice: ('ontouchstart' in window || nav.maxTouchPoints > 0),
  };

  const mathFP = safe(() => [
    Math.acos(0.5), Math.asin(0), Math.cos(Math.PI), Math.sin(Math.PI),
    Math.tan(Math.PI), Math.sinh(1), Math.cosh(1), Math.log(Math.PI),
    Math.sqrt(2), Math.exp(1)
  ].join('|'));

  const mm = (q) => safe(() => window.matchMedia(q).matches);
  const mediaPrefs = {
    colorScheme: mm('(prefers-color-scheme: dark)') ? 'dark' : 'light',
    reducedMotion: mm('(prefers-reduced-motion: reduce)'),
    contrast: mm('(prefers-contrast: more)') ? 'more' : 'no-preference',
    hover: mm('(hover: hover)') ? 'hover' : 'none',
    pointer: mm('(pointer: fine)') ? 'fine' : (mm('(pointer: coarse)') ? 'coarse' : 'none'),
    forcedColors: mm('(forced-colors: active)'),
    hdr: mm('(dynamic-range: high)'),
  };

  const heap = safe(() => {
    const m = performance.memory;
    if (!m) return null;
    return {
      limitGB: (m.jsHeapSizeLimit / 1073741824).toFixed(2),
      usedMB: (m.usedJSHeapSize / 1048576).toFixed(1),
    };
  });

  const speech = await safeAsync(() => new Promise((res) => {
    const go = () => {
      const v = speechSynthesis.getVoices();
      if (v.length) res({ count: v.length, langs: [...new Set(v.map(x => x.lang))].join(', ') });
    };
    speechSynthesis.onvoiceschanged = go; go();
    setTimeout(() => res({ count: 0, langs: 'N/A' }), 1500);
  }));

  const conn = nav.connection || nav.mozConnection || nav.webkitConnection || {};
  const network = {
    effectiveType: conn.effectiveType || 'N/A',
    downlink: conn.downlink || 'N/A',
    rtt: conn.rtt || 'N/A',
    saveData: conn.saveData || false,
  };

  const storage = {
    localStorage: safe(() => !!window.localStorage),
    sessionStorage: safe(() => !!window.sessionStorage),
    indexedDB: safe(() => !!window.indexedDB),
  };

  const plugins = safe(() => Array.from(nav.plugins).map(p => p.name).join(', ') || 'none');

  const canvasFP = safe(() => {
    const c = document.createElement('canvas');
    c.width = 200; c.height = 50;
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top'; ctx.font = '14px Arial';
    ctx.fillStyle = '#f60'; ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069'; ctx.fillText('Honeypot', 2, 15);
    ctx.fillStyle = 'rgba(102,204,0,0.7)'; ctx.fillText('Fingerprint', 4, 17);
    const data = c.toDataURL();
    let h = 0;
    for (let i = 0; i < data.length; i++) { h = ((h << 5) - h) + data.charCodeAt(i); h |= 0; }
    return h.toString(16);
  });

  const webgl = safe(() => {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (!gl) return { renderer: 'N/A', vendor: 'N/A', version: 'N/A' };
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    return {
      renderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
      vendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
      version: gl.getParameter(gl.VERSION),
    };
  });

  const audioFP = await safeAsync(async () => {
    const actx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 44100, 44100);
    const osc = actx.createOscillator(), comp = actx.createDynamicsCompressor();
    osc.type = 'triangle'; osc.frequency.setValueAtTime(10000, actx.currentTime);
    comp.threshold.setValueAtTime(-50, actx.currentTime);
    comp.knee.setValueAtTime(40, actx.currentTime);
    comp.ratio.setValueAtTime(12, actx.currentTime);
    comp.attack.setValueAtTime(0, actx.currentTime);
    comp.release.setValueAtTime(0.25, actx.currentTime);
    osc.connect(comp); comp.connect(actx.destination); osc.start(0);
    const rendered = await actx.startRendering(); osc.stop();
    const buf = rendered.getChannelData(0);
    let sum = 0; for (let i = 4500; i < 5000; i++) sum += Math.abs(buf[i]);
    return sum.toFixed(10);
  });

  const testFonts = ['Arial','Helvetica','Times New Roman','Courier New','Verdana','Georgia','Palatino','Garamond','Comic Sans MS','Trebuchet MS','Arial Black','Impact','Tahoma','Lucida Console','Monaco','Roboto','Open Sans','Ubuntu','Consolas','Segoe UI'];
  const fonts = safe(() => {
    const ctx = document.createElement('canvas').getContext('2d');
    const base = 'monospace', s = 'mmmmmmmmmmlli', size = 72;
    ctx.font = size + 'px ' + base;
    const baseW = ctx.measureText(s).width;
    return testFonts.filter(f => { ctx.font = size + 'px ' + f + ',' + base; return ctx.measureText(s).width !== baseW; }).join(', ');
  });

  const payload = {
    token: HP_TOKEN,
    basic, display, tz, hw, mathFP, mediaPrefs, heap, speech, network,
    storage, plugins, canvasFP, webgl, audioFP, fonts,
    page: { href: location.href, referrer: document.referrer || 'direct', title: document.title },
  };

  try {
    await fetch('/__client_info', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      keepalive: true,
      body: JSON.stringify(payload),
    });
  } catch (e) {}
})();
</script>
"""


def render_fingerprint_js(token):
    return FINGERPRINT_JS_TEMPLATE % {"token": json.dumps(token)}


def build_honeytrap_link():
    """The link an (khong the nhin thay/khong the focus/khong doc duoc boi
    screen reader) tro toi HONEYTRAP_PATH. Nguoi that duyet web binh thuong
    KHONG THE bam vao day - chi bot/scraper doc raw HTML va tu dong theo
    moi href moi "sap bay". Xem analyze_fingerprint() de biet cach cham diem."""
    return (
        f'<a href="/{HONEYTRAP_PATH}" aria-hidden="true" tabindex="-1" '
        'style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;">'
        "internal</a>"
    )


# =====================================================================
# SERVER-SIDE HELPERS
# =====================================================================
def get_client_ip():
    """Lay IP that cua client.
    Uu tien Cf-Connecting-Ip (do Cloudflare dat, kho gia mao khi da khoa
    origin chi nhan traffic tu CF), roi moi den X-Forwarded-For, cuoi cung
    la remote_addr."""
    cf = request.headers.get("Cf-Connecting-Ip", "")
    if cf:
        return cf.strip()
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def is_public_ip(ip):
    if not ip:
        return False
    if ip.startswith(("10.", "192.168.", "127.", "169.254.", "::1", "fc", "fd")):
        return False
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return False
        except (ValueError, IndexError):
            pass
    return True


def ip_geo(ip):
    """Tra cuu IP-geo phia server (ip-api.com, khong can key)."""
    if not is_public_ip(ip):
        return {}
    try:
        fields = "status,country,countryCode,regionName,city,zip,timezone,isp,org,as,query"
        r = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=5)
        d = r.json()
        if d.get("status") == "success":
            return d
    except requests.exceptions.RequestException:
        pass
    return {}


def gmt_str(offset_min):
    """Doi getTimezoneOffset() (phut) sang chuoi GMT+HH:MM."""
    try:
        off = int(offset_min)
    except (TypeError, ValueError):
        return "N/A"
    sign = "+" if off <= 0 else "-"
    a = abs(off)
    return f"GMT{sign}{a // 60}" + (f":{a % 60:02d}" if a % 60 else "")


def esc(v):
    return html.escape(str(v))


# --- Token phien: chung minh POST /__client_info den tu 1 lan load trang
# that (khong phai ai do goi thang API bang curl/script). Stateless (HMAC),
# khong can luu session phia server. Cua so 10 phut du cho ca trang cham nhat. ---
TOKEN_BUCKET_SECONDS = 300  # 5 phut/bucket, chap nhan bucket hien tai + truoc do


def _token_for_bucket(ip, bucket):
    msg = f"{ip}:{bucket}".encode()
    return hmac.new(HONEYPOT_SECRET.encode(), msg, hashlib.sha256).hexdigest()[:32]


def make_token(ip):
    bucket = int(time.time() // TOKEN_BUCKET_SECONDS)
    return _token_for_bucket(ip, bucket)


def verify_token(ip, token):
    if not token:
        return False
    now_bucket = int(time.time() // TOKEN_BUCKET_SECONDS)
    for bucket in (now_bucket, now_bucket - 1):
        if hmac.compare_digest(_token_for_bucket(ip, bucket), str(token)):
            return True
    return False


# --- Rate limit tho theo IP cho /__client_info, tranh bi spam/flood keo dai
# Telegram (endpoint nay khong the doi hoi auth vi phai nhan duoc ca cac
# request "kha nghi" khong co token hop le). ---
_RATE_LIMIT_MAX = 5
_RATE_LIMIT_WINDOW = 60
_rate_hits = defaultdict(deque)
_rate_lock = threading.Lock()


def rate_limited(ip):
    now = time.time()
    with _rate_lock:
        hits = _rate_hits[ip]
        while hits and now - hits[0] > _RATE_LIMIT_WINDOW:
            hits.popleft()
        if len(hits) >= _RATE_LIMIT_MAX:
            return True
        hits.append(now)
        return False


def log_hit(fp, ctx, score, verdict):
    """Ghi lai fingerprint tho ra file JSONL, doc lap voi Telegram, de sau
    nay doi chieu/phan tich (vd cung 1 fingerprint xuat hien o nhieu IP)."""
    record = {
        "ts": time.time(),
        "ip": ctx.get("ip"),
        "score": score,
        "verdict": verdict,
        "ctx": ctx,
        "fp": fp,
    }
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def analyze_fingerprint(fp, ctx=None):
    """Cham diem nghi van dua tren cac mau thuan trong fingerprint
    (UA gia mao, headless/automation...). Tra ve (diem 0-100, nhan, list ly do,
    da sap xep theo trong so giam dan)."""
    ctx = ctx or {}
    b = fp.get("basic", {}) or {}
    d = fp.get("display", {}) or {}
    hw = fp.get("hw", {}) or {}
    mp = fp.get("mediaPrefs", {}) or {}
    speech = fp.get("speech", {}) or {}
    gl = fp.get("webgl", {}) or {}
    page = fp.get("page", {}) or {}

    ua = str(b.get("userAgent") or "")
    is_mobile_ua = bool(re.search(r"Mobile|iPhone|Android|iPad", ua, re.I))

    reasons = []

    def flag(points, text):
        reasons.append((points, text))

    if HONEYTRAP_PATH and HONEYTRAP_PATH in str(page.get("href") or ""):
        flag(60, "Da theo duong link AN (honeytrap) - nguoi that khong the nhin thay/bam vao day, "
                 "gan nhu chac chan la bot/scanner tu dong doc HTML")

    if not ctx.get("token_ok", True):
        flag(30, "Thieu token phien hop le khi goi /__client_info (co the la POST truc tiep bang "
                 "script/curl, khong qua load trang that)")

    if ctx.get("sec_fetch_mode") is None:
        flag(20, "Thieu header Sec-Fetch-* (dau hieu request khong den tu dieu huong trinh duyet "
                 "that, vd script/HTTP client don gian)")

    if b.get("webdriver") is True:
        flag(40, "navigator.webdriver = true (dau hieu automation: Selenium/Playwright/Puppeteer)")

    if is_mobile_ua and hw.get("isTouchDevice") is False:
        flag(25, "UA khai la mobile nhung thiet bi khong co touch")

    if is_mobile_ua and mp.get("hover") == "hover":
        flag(20, "UA khai la mobile nhung hover=hover (dau vao la chuot that, khong phai cam ung)")

    if is_mobile_ua and mp.get("pointer") == "fine":
        flag(15, "UA khai la mobile nhung pointer=fine (do chinh xac chuot; dien thoai that la 'coarse')")

    try:
        dpr = float(d.get("dpr"))
        if is_mobile_ua and dpr <= 1:
            flag(10, f"UA khai la mobile nhung DPR={d.get('dpr')} (dien thoai that luon >= 2)")
    except (TypeError, ValueError):
        pass

    renderer = str(gl.get("renderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "software rasterizer")):
        flag(30, f"WebGL renderer la software rasterizer ({esc(gl.get('renderer'))}) - dau hieu headless/khong co GPU that")

    if speech.get("count") == 0:
        flag(10, "Khong co giong doc TTS nao (thuong gap o headless browser)")

    if fp.get("canvasFP") in (None, "N/A"):
        flag(15, "Canvas fingerprint bi chan/loi (co the do automation chan API)")

    if fp.get("audioFP") in (None, "N/A"):
        flag(15, "Audio fingerprint bi chan/loi (co the do automation chan API)")

    if hw.get("cpuCores") == "N/A" or hw.get("deviceMemoryGB") == "N/A":
        flag(5, "Thieu thong tin phan cung CPU/RAM")

    if d.get("viewport") in (None, "0x0", "N/A"):
        flag(25, "Viewport 0x0 hoac khong xac dinh (dau hieu ro cua headless/scriptless client)")

    score = min(sum(p for p, _ in reasons), 100)
    if score >= 60:
        verdict = "🔴 HIGH"
    elif score >= 30:
        verdict = "🟡 MEDIUM"
    else:
        verdict = "🟢 LOW"

    ordered = [text for _, text in sorted(reasons, key=lambda x: -x[0])]
    return score, verdict, ordered


def build_message(fp, ctx, score, verdict, reasons):
    """Ghep context server-side (IP/geo/CF) voi fingerprint client thanh 1 tin nhan HTML."""
    b = fp.get("basic", {}) or {}
    d = fp.get("display", {}) or {}
    tz = fp.get("tz", {}) or {}
    hw = fp.get("hw", {}) or {}
    mp = fp.get("mediaPrefs", {}) or {}
    heap = fp.get("heap") or {}
    speech = fp.get("speech", {}) or {}
    net = fp.get("network", {}) or {}
    st = fp.get("storage", {}) or {}
    gl = fp.get("webgl", {}) or {}
    page = fp.get("page", {}) or {}
    geo = ctx.get("geo", {}) or {}

    lines = [
        "🚨 <b>HONEYPOT HIT</b> 🚨",
        "",
        f"<b>🎯 Suspicion Score: {score}/100 — {verdict}</b>",
    ]
    if reasons:
        lines += [f"• {esc(r)}" for r in reasons]
    else:
        lines.append("• Khong phat hien mau thuan ro ret")
    lines += [
        "",
        "<b>🌐 IP &amp; Geolocation</b>",
        f"IP: <code>{esc(ctx.get('ip') or geo.get('query') or 'N/A')}</code>",
        f"ISP: {esc(geo.get('isp') or 'N/A')}",
        f"Org/AS: {esc(geo.get('org') or 'N/A')} | {esc(geo.get('as') or 'N/A')}",
        f"Location: {esc(geo.get('city') or '')}, {esc(geo.get('regionName') or '')}, "
        f"{esc(geo.get('country') or '')} ({esc(geo.get('countryCode') or ctx.get('cf_country') or '')})",
        f"Zip: {esc(geo.get('zip') or 'N/A')} | GeoIP TZ: {esc(geo.get('timezone') or 'N/A')}",
        "",
        "<b>☁️ Cloudflare Context</b>",
        f"Ray ID: <code>{esc(ctx.get('ray_id') or 'N/A')}</code> | CF-Country: {esc(ctx.get('cf_country') or 'N/A')}",
        f"Host: {esc(ctx.get('host') or 'N/A')}",
        "",
        "<b>💻 Device &amp; OS</b>",
        f"UA: {esc(b.get('userAgent'))}",
        f"Platform: {esc(b.get('platform'))} | Vendor: {esc(b.get('vendor'))}",
        f"Language: {esc(b.get('language'))} | {esc(b.get('languages'))}",
        f"CPU Cores: {esc(hw.get('cpuCores'))} | RAM: ≥{esc(hw.get('deviceMemoryGB'))} GB (browser-capped)",
        f"Heap: {esc(heap.get('limitGB'))} GB limit | Used: {esc(heap.get('usedMB'))} MB",
        f"Touch: {esc(hw.get('isTouchDevice'))} (maxPoints: {esc(hw.get('maxTouchPoints'))})",
        "",
        "<b>🖥 Screen &amp; Display</b>",
        f"Physical: {esc(d.get('physical'))} | CSS: {esc(d.get('css'))} | DPR: {esc(d.get('dpr'))}",
        f"Available: {esc(d.get('avail'))} | Viewport: {esc(d.get('viewport'))}",
        f"Color/Pixel Depth: {esc(d.get('colorDepth'))} / {esc(d.get('pixelDepth'))} | Orientation: {esc(d.get('orientation'))}",
        "",
        "<b>🌐 Network</b>",
        f"Connection: {esc(net.get('effectiveType'))} | Downlink: {esc(net.get('downlink'))} Mbps | RTT: {esc(net.get('rtt'))} ms",
        f"SaveData: {esc(net.get('saveData'))} | Online: {esc(b.get('onLine'))}",
        "",
        "<b>⏰ Time &amp; Locale</b>",
        f"Browser TZ: {esc(tz.get('timezone'))} ({gmt_str(tz.get('offsetMin'))})",
        f"Locale: {esc(tz.get('locale'))} | Visit: {esc(tz.get('timestamp'))}",
        "",
        "<b>🔍 Fingerprints</b>",
        f"Canvas Hash: {esc(fp.get('canvasFP'))}",
        f"Audio FP: {esc(fp.get('audioFP'))}",
        f"Math FP: {esc(str(fp.get('mathFP'))[:60])}...",
        f"WebGL Renderer: {esc(gl.get('renderer'))}",
        f"WebGL Vendor: {esc(gl.get('vendor'))} | Version: {esc(gl.get('version'))}",
        "",
        "<b>🔌 Storage &amp; Display Prefs</b>",
        f"localStorage: {esc(st.get('localStorage'))} | sessionStorage: {esc(st.get('sessionStorage'))} | indexedDB: {esc(st.get('indexedDB'))}",
        f"Color scheme: {esc(mp.get('colorScheme'))} | Contrast: {esc(mp.get('contrast'))} | HDR: {esc(mp.get('hdr'))}",
        f"Hover: {esc(mp.get('hover'))} | Pointer: {esc(mp.get('pointer'))} | Forced colors: {esc(mp.get('forcedColors'))}",
        "",
        "<b>🗣 Speech Voices</b>",
        f"Count: {esc(speech.get('count'))} | Langs: {esc(speech.get('langs'))}",
        "",
        "<b>🔎 Browser Misc</b>",
        f"DNT: {esc(b.get('doNotTrack'))} | Plugins: {esc(b.get('plugins') or fp.get('plugins'))}",
        f"Fonts: {esc(fp.get('fonts'))}",
        "",
        "<b>📄 Page Context</b>",
        f"URL: {esc(page.get('href'))}",
        f"Referrer: {esc(page.get('referrer'))}",
    ]
    return "\n".join(lines)


def send_telegram(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=5,
        )
    except requests.exceptions.RequestException:
        pass


# =====================================================================
# ROUTES
# =====================================================================
@app.route("/__client_info", methods=["POST"])
def client_info():
    """Nhan fingerprint tu client, ghep context server-side, gui Telegram."""
    ip = get_client_ip()
    if rate_limited(ip):
        return "", 204

    fp = request.get_json(silent=True) or {}
    ctx = {
        "ip": ip,
        "geo": ip_geo(ip),
        "ray_id": request.headers.get("Cf-Ray", "")[:16],
        "cf_country": request.headers.get("Cf-Ipcountry", ""),
        "host": request.headers.get("Host", ""),
        "token_ok": verify_token(ip, fp.get("token")),
        "sec_fetch_mode": request.headers.get("Sec-Fetch-Mode"),
    }
    score, verdict, reasons = analyze_fingerprint(fp, ctx)
    log_hit(fp, ctx, score, verdict)
    send_telegram(build_message(fp, ctx, score, verdict, reasons))
    return "", 204


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def index(path):
    """Phuc vu trang loi Cloudflare gia, chen script fingerprint im lang."""
    host = request.headers.get("Host", "") or TARGET_DOMAIN
    ray_id = request.headers.get("Cf-Ray", "")[:16]
    client_ip = get_client_ip()

    params: ErrorPageParams = {
        "error_code": 500,
        "html_title": f"{host} | 500 Internal Server Error",
        "title": "Internal server error",
        "browser_status": {"status": "ok"},
        "cloudflare_status": {"status": "error", "status_text": "Error"},
        "host_status": {"status": "ok", "location": host},
        "error_source": "cloudflare",
        "what_happened": "<p>There is an internal server error on Cloudflare's network.</p>",
        "what_can_i_do": "<p>Please try again in a few minutes.</p>",
        "ray_id": ray_id,
        "client_ip": client_ip,
    }

    html_out = render_cf_error_page(params)
    injected = build_honeytrap_link() + render_fingerprint_js(make_token(client_ip))
    html_out = html_out.replace("</body>", injected + "\n</body>")
    return html_out, params["error_code"]


if __name__ == "__main__":
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
