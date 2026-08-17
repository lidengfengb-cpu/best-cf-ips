import ipaddress
import json
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import TYPE_CHECKING

from curl_cffi import requests as cf_requests

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

try:
    from ip2region import util
    from ip2region.searcher import new_with_buffer
except ImportError:
    util = None
    new_with_buffer = None

if TYPE_CHECKING:
    from ip2region.searcher import Searcher
    from playwright.sync_api import Browser


SOURCES: dict[str, str] = {
    'https://www.wetest.vip/page/cloudfront/address_v4.html': 'WeTest',
    'https://api.uouin.com/cloudflare.html': 'UOUIN',
    'https://bestcf.pages.dev/xinyitang3/ipv4.txt': 'Mia',
    'https://bestcf.pages.dev/tiancheng/all.txt': 'Tiancheng',
    'https://raw.githubusercontent.com/gslege/CloudflareIP/refs/heads/main/SG.txt': 'Gslege-SG',
    'https://bestcf.pages.dev/s5gy/hk.txt': 's5gy-hk',
    'https://bestcf.pages.dev/s5gy/jp.txt': 's5gy-jp',
    'https://raw.githubusercontent.com/gslege/CloudflareIP/refs/heads/main/US.txt': 'Gslege-US',
    'https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestCF/bestcfv4.txt': 'IPDB',
    'https://vps789.com/openApi/cfIpApi': 'VPS789',
    'https://api.4ce.cn/api/bestCFIP': 'vvhan',
    'https://bestcf.pages.dev/luoli/all.txt': 'LuoLi',
}

DEFAULT_PORT: int = 443
HEADERS: dict[str, str] = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0',
}
IPV4_ENDPOINT_PATTERN: str = (
    r'(?<![\w.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})'
    r'(?::([0-9]{1,5}))?(?![\w.:/])'
)
OUTPUT_FILE: Path = Path('best-cf-ipv4.txt')
XDB_URL: str = 'https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb'
XDB_FILE: Path = Path(__file__).resolve().parent / 'data' / 'ip2region_v4.xdb'
MAX_RETRIES: int = 3
RETRY_BACKOFF_FACTOR: float = 2.0


def _session() -> cf_requests.Session:
    """Create a session with Chrome TLS fingerprint impersonation."""
    session = cf_requests.Session(impersonate='chrome')
    session.headers.update(HEADERS)
    return session


def fetch(session: cf_requests.Session, url: str, timeout: int = 15) -> str:
    """Fetch a URL with retry support and return response text."""
    last_err: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = session.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            last_err = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_FACTOR ** attempt)
    assert last_err is not None
    raise last_err


def extract_ipv4(text: str) -> set[tuple[str, str]]:
    """Extract valid IPv4 endpoints, preserving explicitly provided ports."""
    stripped = text.lstrip('\ufeff\t\n\r ')
    if stripped.startswith(('{', '[')):
        try:
            return extract_json_ipv4(json.loads(stripped))
        except json.JSONDecodeError:
            return set()
    if stripped.startswith('<'):
        parser = VisibleTextParser()
        parser.feed(text)
        text = parser.text

    endpoints: set[tuple[str, str]] = set()
    for match in re.finditer(IPV4_ENDPOINT_PATTERN, text):
        try:
            ip = str(ipaddress.ip_address(match.group(1)))
            port_number = int(match.group(2) or DEFAULT_PORT)
            if not 1 <= port_number <= 65535:
                continue
            endpoints.add((ip, str(port_number)))
        except ValueError:
            continue
    return endpoints


def extract_json_ipv4(value: object) -> set[tuple[str, str]]:
    """Extract endpoints only from fields explicitly named 'ip'."""
    if isinstance(value, dict):
        endpoints: set[tuple[str, str]] = set()
        for key, child in value.items():
            if key.casefold() == 'ip' and isinstance(child, str):
                endpoints.update(extract_ipv4(child))
            else:
                endpoints.update(extract_json_ipv4(child))
        return endpoints
    if isinstance(value, list):
        endpoints: set[tuple[str, str]] = set()
        for child in value:
            endpoints.update(extract_json_ipv4(child))
        return endpoints
    return set()


class VisibleTextParser(HTMLParser):
    """Collect visible HTML text while ignoring scripts and styles."""

    def __init__(self) -> None:
        super().__init__()
        self._ignored_depth = 0
        self._parts: list[str] = []

    @property
    def text(self) -> str:
        return ' '.join(self._parts)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in {'script', 'style'}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {'script', 'style'} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self._parts.append(data)


def sort_endpoints(endpoints: set[tuple[str, str]]) -> list[tuple[str, str]]:
    """Sort endpoints deterministically by IP and numeric port."""
    return sorted(endpoints, key=lambda endpoint: (ipaddress.ip_address(endpoint[0]), int(endpoint[1])))


def country_to_flag(code: str) -> str:
    if len(code) != 2 or code == 'XX':
        return ''
    return chr(ord(code[0]) - 65 + 0x1F1E6) + chr(ord(code[1]) - 65 + 0x1F1E6)


COUNTRY_ZH: dict[str, str] = {
    'AF': '阿富汗', 'AX': '奥兰群岛', 'AL': '阿尔巴尼亚', 'DZ': '阿尔及利亚',
    'AS': '美属萨摩亚', 'AD': '安道尔', 'AO': '安哥拉', 'AI': '安圭拉',
    'AQ': '南极洲', 'AG': '安提瓜和巴布达', 'AR': '阿根廷', 'AM': '亚美尼亚',
    'AW': '阿鲁巴', 'AU': '澳大利亚', 'AT': '奥地利', 'AZ': '阿塞拜疆',
    'BS': '巴哈马', 'BH': '巴林', 'BD': '孟加拉国', 'BB': '巴巴多斯',
    'BY': '白俄罗斯', 'BE': '比利时', 'BZ': '伯利兹', 'BJ': '贝宁',
    'BM': '百慕大', 'BT': '不丹', 'BO': '玻利维亚', 'BQ': '荷兰加勒比区',
    'BA': '波黑', 'BW': '博茨瓦纳', 'BV': '布韦岛', 'BR': '巴西',
    'IO': '英属印度洋领地', 'BN': '文莱', 'BG': '保加利亚', 'BF': '布基纳法索',
    'BI': '布隆迪', 'CV': '佛得角', 'KH': '柬埔寨', 'CM': '喀麦隆',
    'CA': '加拿大', 'KY': '开曼群岛', 'CF': '中非共和国', 'TD': '乍得',
    'CL': '智利', 'CN': '中国', 'CX': '圣诞岛', 'CC': '科科斯群岛',
    'CO': '哥伦比亚', 'KM': '科摩罗', 'CG': '刚果', 'CD': '刚果民主共和国',
    'CK': '库克群岛', 'CR': '哥斯达黎加', 'CI': '科特迪瓦', 'HR': '克罗地亚',
    'CU': '古巴', 'CW': '库拉索', 'CY': '塞浦路斯', 'CZ': '捷克',
    'DK': '丹麦', 'DJ': '吉布提', 'DM': '多米尼克', 'DO': '多米尼加共和国',
    'EC': '厄瓜多尔', 'EG': '埃及', 'SV': '萨尔瓦多', 'GQ': '赤道几内亚',
    'ER': '厄立特里亚', 'EE': '爱沙尼亚', 'SZ': '斯威士兰', 'ET': '埃塞俄比亚',
    'FK': '福克兰群岛', 'FO': '法罗群岛', 'FJ': '斐济', 'FI': '芬兰',
    'FR': '法国', 'GF': '法属圭亚那', 'PF': '法属波利尼西亚', 'TF': '法属南部领地',
    'GA': '加蓬', 'GM': '冈比亚', 'GE': '格鲁吉亚', 'DE': '德国',
    'GH': '加纳', 'GI': '直布罗陀', 'GR': '希腊', 'GL': '格陵兰',
    'GD': '格林纳达', 'GP': '瓜德罗普', 'GU': '关岛', 'GT': '危地马拉',
    'GG': '根西岛', 'GN': '几内亚', 'GW': '几内亚比绍', 'GY': '圭亚那',
    'HT': '海地', 'HM': '赫德岛和麦克唐纳群岛', 'VA': '梵蒂冈', 'HN': '洪都拉斯',
    'HK': '香港', 'HU': '匈牙利', 'IS': '冰岛', 'IN': '印度',
    'ID': '印度尼西亚', 'IR': '伊朗', 'IQ': '伊拉克', 'IE': '爱尔兰',
    'IM': '马恩岛', 'IL': '以色列', 'IT': '意大利', 'JM': '牙买加',
    'JP': '日本', 'JE': '泽西岛', 'JO': '约旦', 'KZ': '哈萨克斯坦',
    'KE': '肯尼亚', 'KI': '基里巴斯', 'KP': '朝鲜', 'KR': '韩国',
    'KW': '科威特', 'KG': '吉尔吉斯斯坦', 'LA': '老挝', 'LV': '拉脱维亚',
    'LB': '黎巴嫩', 'LS': '莱索托', 'LR': '利比里亚', 'LY': '利比亚',
    'LI': '列支敦士登', 'LT': '立陶宛', 'LU': '卢森堡', 'MO': '澳门',
    'MG': '马达加斯加', 'MW': '马拉维', 'MY': '马来西亚', 'MV': '马尔代夫',
    'ML': '马里', 'MT': '马耳他', 'MH': '马绍尔群岛', 'MQ': '马提尼克',
    'MR': '毛里塔尼亚', 'MU': '毛里求斯', 'YT': '马约特', 'MX': '墨西哥',
    'FM': '密克罗尼西亚联邦', 'MD': '摩尔多瓦', 'MC': '摩纳哥', 'MN': '蒙古',
    'ME': '黑山', 'MS': '蒙特塞拉特', 'MA': '摩洛哥', 'MZ': '莫桑比克',
    'MM': '缅甸', 'NA': '纳米比亚', 'NR': '瑙鲁', 'NP': '尼泊尔',
    'NL': '荷兰', 'NC': '新喀里多尼亚', 'NZ': '新西兰', 'NI': '尼加拉瓜',
    'NE': '尼日尔', 'NG': '尼日利亚', 'NU': '纽埃', 'NF': '诺福克岛',
    'MK': '北马其顿', 'MP': '北马里亚纳群岛', 'NO': '挪威', 'OM': '阿曼',
    'PK': '巴基斯坦', 'PW': '帕劳', 'PS': '巴勒斯坦', 'PA': '巴拿马',
    'PG': '巴布亚新几内亚', 'PY': '巴拉圭', 'PE': '秘鲁', 'PH': '菲律宾',
    'PN': '皮特凯恩群岛', 'PL': '波兰', 'PT': '葡萄牙', 'PR': '波多黎各',
    'QA': '卡塔尔', 'RE': '留尼汪', 'RO': '罗马尼亚', 'RU': '俄罗斯',
    'RW': '卢旺达', 'BL': '圣巴泰勒米', 'SH': '圣赫勒拿', 'KN': '圣基茨和尼维斯',
    'LC': '圣卢西亚', 'MF': '圣马丁岛', 'PM': '圣皮埃尔和密克隆', 'VC': '圣文森特和格林纳丁斯',
    'WS': '萨摩亚', 'SM': '圣马力诺', 'ST': '圣多美和普林西比', 'SA': '沙特阿拉伯',
    'SN': '塞内加尔', 'RS': '塞尔维亚', 'SC': '塞舌尔', 'SL': '塞拉利昂',
    'SG': '新加坡', 'SX': '荷属圣马丁', 'SK': '斯洛伐克', 'SI': '斯洛文尼亚',
    'SB': '所罗门群岛', 'SO': '索马里', 'ZA': '南非', 'GS': '南乔治亚和南桑威奇群岛',
    'SS': '南苏丹', 'ES': '西班牙', 'LK': '斯里兰卡', 'SD': '苏丹',
    'SR': '苏里南', 'SJ': '斯瓦尔巴和扬马延', 'SE': '瑞典', 'CH': '瑞士',
    'SY': '叙利亚', 'TW': '台湾', 'TJ': '塔吉克斯坦', 'TZ': '坦桑尼亚',
    'TH': '泰国', 'TL': '东帝汶', 'TG': '多哥', 'TK': '托克劳',
    'TO': '汤加', 'TT': '特立尼达和多巴哥', 'TN': '突尼斯', 'TR': '土耳其',
    'TM': '土库曼斯坦', 'TC': '特克斯和凯科斯群岛', 'TV': '图瓦卢', 'UG': '乌干达',
    'UA': '乌克兰', 'AE': '阿联酋', 'GB': '英国', 'US': '美国',
    'UM': '美国本土外小岛屿', 'UY': '乌拉圭', 'UZ': '乌兹别克斯坦', 'VU': '瓦努阿图',
    'VE': '委内瑞拉', 'VN': '越南', 'VG': '英属维尔京群岛', 'VI': '美属维尔京群岛',
    'WF': '瓦利斯和富图纳', 'EH': '西撒哈拉', 'YE': '也门', 'ZM': '赞比亚',
    'ZW': '津巴布韦',
}


def country_to_zh(code: str) -> str:
    """Map ISO-3166 code to a Chinese name, falling back to the code itself."""
    return COUNTRY_ZH.get(code, code)


def _ensure_xdb() -> None:
    """Download the offline xdb database if missing."""
    if XDB_FILE.exists():
        return
    XDB_FILE.parent.mkdir(parents=True, exist_ok=True)
    print(f'Downloading {XDB_URL} ...')
    with _session() as sess:
        resp = sess.get(XDB_URL, timeout=120)
        resp.raise_for_status()
        XDB_FILE.write_bytes(resp.content)


_searcher = None


def _get_searcher() -> 'Searcher':
    """Lazily create a full-memory xdb searcher."""
    global _searcher
    if new_with_buffer is None:
        raise RuntimeError('ip2region not installed; run: pip install -r .github/scripts/requirements.txt')
    if _searcher is None:
        _ensure_xdb()
        _searcher = new_with_buffer(
            util.version_from_header(util.load_header_from_file(str(XDB_FILE))),
            util.load_content_from_file(str(XDB_FILE)),
        )
    return _searcher


def lookup_country(ip: str) -> str:
    """Look up ISO-3166 country code offline via ip2region, return 'XX' on failure."""
    try:
        region = _get_searcher().search(ip)
        code = region.split('|')[-1].strip()
        if re.fullmatch(r'[A-Z]{2}', code):
            return code
    except Exception:
        pass
    return 'XX'


def beijing_timestamp() -> str:
    """Return current Beijing time as YYYY-MM-DD HH:MM string."""
    return (datetime.now(timezone.utc) + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')


_browser = None
_pw = None


def _get_browser() -> 'Browser':
    """Lazily start a reusable headless Chromium instance."""
    global _browser, _pw
    if sync_playwright is None:
        raise RuntimeError('playwright not installed; run: pip install playwright && playwright install chromium')
    if _browser is None:
        pw = sync_playwright().start()
        try:
            browser = pw.chromium.launch(headless=True)
        except Exception:
            pw.stop()
            raise
        _pw = pw
        _browser = browser
    return _browser


def fetch_rendered(url: str, timeout: int = 30000) -> str:
    """Render a JS page with headless Chromium and return the final HTML."""
    context = _get_browser().new_context(user_agent=HEADERS['User-Agent'])
    try:
        page = context.new_page()
        page.goto(url, wait_until='networkidle', timeout=timeout)
        return page.content()
    finally:
        context.close()


def close_browser() -> None:
    """Close the reusable browser and Playwright runtime if they were started."""
    global _browser, _pw
    try:
        if _browser is not None:
            _browser.close()
    finally:
        _browser = None
        if _pw is not None:
            try:
                _pw.stop()
            finally:
                _pw = None


def collect_ips(session: cf_requests.Session) -> set[tuple[str, str]]:
    """Collect IPv4 endpoints, degrading from HTTP to headless browser.

    A source is considered fetched successfully only when it yields at least
    one valid IPv4 address; otherwise the next fetcher tier is tried.
    """
    all_ips: set[tuple[str, str]] = set()
    tiers = [
        ('HTTP', lambda u: fetch(session, u)),
        ('Browser', fetch_rendered),
    ]
    for url, name in SOURCES.items():
        for label, fetcher in tiers:
            try:
                ips = extract_ipv4(fetcher(url))
            except Exception as e:
                print(f'  [{name}] {label} failed: {e}')
                continue
            if ips:
                all_ips.update(ips)
                print(f'  [{name}] {label}: {len(ips)} IPv4')
                break
            print(f'  [{name}] {label}: 0 IPv4, trying next tier')
        else:
            print(f'  [{name}] all fetchers failed')
    return all_ips


def enrich_locations(ips: set[tuple[str, str]]) -> dict[str, str]:
    """Query geographic locations for all IPv4 endpoints via the offline database."""
    _get_searcher()
    entries: dict[str, str] = {}
    for ip, port in ips:
        entries[f'{ip}:{port}'] = lookup_country(ip)
    return entries


def main() -> int:
    """Collect Cloudflare IPs, query locations, and write result file."""
    print('Collecting Cloudflare IPs...\n')

    session = _session()
    try:
        all_ips = collect_ips(session)
        if not all_ips:
            print('No IPs collected, skip')
            return 1
        print(f'\n{len(all_ips)} unique IPv4')

        print('Querying locations...')
        entries = enrich_locations(all_ips)

        tmp = OUTPUT_FILE.with_suffix('.tmp')
        timestamp = beijing_timestamp()
        with tmp.open('w', encoding='utf-8') as f:
            f.write(f'#{len(entries)} bestips updated at {timestamp}\n')
            for ip, port in sort_endpoints(all_ips):
                ip_port = f'{ip}:{port}'
                f.write(f'{ip_port}#{country_to_zh(entries[ip_port])} {country_to_flag(entries[ip_port])}\n')
        tmp.replace(OUTPUT_FILE)
        print(f'\n{len(entries)} IPs written to {OUTPUT_FILE}')
        return 0
    finally:
        try:
            session.close()
        finally:
            close_browser()


if __name__ == '__main__':
    sys.exit(main())
