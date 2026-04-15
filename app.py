#!/usr/bin/env python3
"""
PhishScan Pro - Advanced Phishing URL Detector
For use on Kali Linux / security research environments
"""

from flask import Flask, request, jsonify, send_from_directory
import re, socket, whois, dns.resolver, time, os, ssl, hashlib
import requests
import tldextract
from urllib.parse import urlparse, unquote
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init as colorama_init
import json

colorama_init(autoreset=True)

app = Flask(__name__, static_folder='static', static_url_path='')

# ── Threat intelligence lists ──────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    'login','password','bank','paypal','verify','account','urgent','security',
    'update','confirm','suspend','billing','invoice','alert','support','helpdesk',
    'signin','signup','credential','recover','unlock','validate','authorize',
    'secure','wallet','crypto','bitcoin','reward','prize','winner','free',
    'limited','offer','click','webscr','cmd','dispatch','ebayisapi','appleid'
]

HIGH_RISK_TLDS = ['tk','ml','ga','cf','gq','ru','xyz','top','click','zip','mov','loan','work']

TRUSTED_BRANDS = [
    'paypal','google','apple','microsoft','amazon','facebook','instagram',
    'twitter','netflix','dropbox','linkedin','chase','wellsfargo','bankofamerica',
    'steam','discord','github','adobe','zoom','spotify'
]

URL_SHORTENERS = [
    'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','buff.ly','short.link',
    'is.gd','cutt.ly','rebrand.ly','tiny.cc','bl.ink'
]

SUSPICIOUS_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',       # IP address as host
    r'@',                                            # @ in URL (redirects)
    r'\/\/.*@',                                      # user:pass@host
    r'[a-z0-9]-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',  # multiple hyphens
    r'xn--',                                         # Punycode/IDN homograph
    r'%[0-9a-fA-F]{2}',                             # excessive URL encoding
]

# ── Analysis functions ─────────────────────────────────────────────────────────

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        if w.creation_date:
            cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            return max(0, int((datetime.now() - cd).days))
    except:
        pass
    return -1  # -1 = unknown


def check_mx_records(domain):
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except:
        return False


def check_ssl_cert(domain):
    result = {'valid': False, 'issuer': 'N/A', 'expiry': 'N/A', 'self_signed': False, 'days_left': -1}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            result['valid'] = True
            issuer_dict = dict(x[0] for x in cert.get('issuer', []))
            result['issuer'] = issuer_dict.get('organizationName', 'Unknown')
            result['self_signed'] = issuer_dict.get('organizationName') == \
                                    dict(x[0] for x in cert.get('subject', [])).get('organizationName')
            exp = cert.get('notAfter', '')
            if exp:
                exp_dt = datetime.strptime(exp, '%b %d %H:%M:%S %Y %Z')
                result['expiry'] = exp_dt.strftime('%Y-%m-%d')
                result['days_left'] = (exp_dt - datetime.utcnow()).days
    except ssl.SSLCertVerificationError:
        result['valid'] = False
    except Exception:
        pass
    return result


def check_redirect_chain(url):
    chain = []
    try:
        resp = requests.get(url, allow_redirects=True, timeout=8,
                            headers={'User-Agent': 'Mozilla/5.0'}, stream=True)
        for r in resp.history:
            chain.append({'code': r.status_code, 'url': r.url})
        chain.append({'code': resp.status_code, 'url': resp.url})
    except:
        pass
    return chain


def check_dns_records(domain):
    records = {}
    for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except:
            records[rtype] = []
    return records


def check_spf_dkim(domain):
    spf, dmarc = False, False
    try:
        txts = dns.resolver.resolve(domain, 'TXT')
        for r in txts:
            s = str(r).lower()
            if 'v=spf1' in s:
                spf = True
            if 'v=dmarc1' in s:
                dmarc = True
    except:
        pass
    # Check _dmarc subdomain too
    if not dmarc:
        try:
            txts = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for r in txts:
                if 'v=dmarc1' in str(r).lower():
                    dmarc = True
        except:
            pass
    return spf, dmarc


def check_url_shortener(domain):
    return any(s in domain.lower() for s in URL_SHORTENERS)


def check_brand_impersonation(domain, url):
    """Check if URL impersonates a known trusted brand."""
    hits = []
    domain_lower = domain.lower()
    url_lower = url.lower()
    ext = tldextract.extract(domain)
    registered = ext.domain.lower()

    for brand in TRUSTED_BRANDS:
        in_url = brand in url_lower
        is_official = registered == brand or registered.startswith(brand + '.')
        # Brand in subdomain or path but not the registered domain
        if in_url and not is_official:
            hits.append(brand)
    return hits


def check_homograph(domain):
    """Detect IDN homograph / look-alike characters."""
    suspicious_chars = re.search(r'[^\x00-\x7F]', domain)
    has_punycode = 'xn--' in domain.lower()
    return bool(suspicious_chars or has_punycode)


def entropy(s):
    """Shannon entropy — high entropy = random/DGA domain."""
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * __import__('math').log2(p) for p in prob)


def check_dga(domain):
    """Heuristic detection of domain generation algorithm (DGA) domains."""
    ext = tldextract.extract(domain)
    label = ext.domain
    if not label:
        return False
    ent = entropy(label)
    vowels = sum(1 for c in label if c in 'aeiou')
    vowel_ratio = vowels / len(label) if label else 0
    # Typical DGA: high entropy, very few vowels, long label
    return ent > 3.5 and vowel_ratio < 0.15 and len(label) > 10


def subdomain_count(domain):
    ext = tldextract.extract(domain)
    if ext.subdomain:
        return len(ext.subdomain.split('.'))
    return 0


def url_features(url, domain):
    """Extract structural URL features."""
    parsed = urlparse(url)
    return {
        'length': len(url),
        'depth': len([p for p in parsed.path.split('/') if p]),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_at': url.count('@'),
        'num_digits': sum(c.isdigit() for c in domain),
        'has_port': bool(parsed.port and parsed.port not in (80, 443)),
        'has_fragment': bool(parsed.fragment),
        'has_query': bool(parsed.query),
        'encoded_chars': len(re.findall(r'%[0-9a-fA-F]{2}', url)),
        'subdomain_count': subdomain_count(domain),
    }


# ── Scoring engine ─────────────────────────────────────────────────────────────

def compute_score(url, domain, age, ssl_info, redirect_chain,
                  dns_records, spf, dmarc, features):
    score = 0
    reasons = []
    details = []

    # 1. HTTPS
    if not url.startswith('https://'):
        score += 20
        reasons.append('❌ No HTTPS (plain HTTP)')

    # 2. SSL certificate issues
    if url.startswith('https://'):
        if not ssl_info['valid']:
            score += 25
            reasons.append('❌ Invalid/untrusted SSL certificate')
        elif ssl_info['self_signed']:
            score += 15
            reasons.append('⚠️ Self-signed certificate')
        elif ssl_info['days_left'] != -1 and ssl_info['days_left'] < 15:
            score += 10
            reasons.append(f'⚠️ SSL expires in {ssl_info["days_left"]} days')

    # 3. Domain age
    if age == -1:
        score += 10
        reasons.append('⚠️ Domain age unknown (WHOIS blocked)')
    elif 0 < age < 30:
        score += 35
        reasons.append(f'🆕 Domain only {age} days old')
    elif 30 <= age < 90:
        score += 20
        reasons.append(f'🆕 Domain is {age} days old')

    # 4. Suspicious keywords
    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    for kw in kw_hits[:3]:
        score += 12
        reasons.append(f'⚠️ Suspicious keyword: "{kw}"')

    # 5. Brand impersonation
    brand_hits = check_brand_impersonation(domain, url)
    for brand in brand_hits:
        score += 30
        reasons.append(f'🎭 Brand impersonation: "{brand}"')

    # 6. High-risk TLD
    tld = domain.rsplit('.', 1)[-1].lower()
    if tld in HIGH_RISK_TLDS:
        score += 15
        reasons.append(f'⚠️ High-risk TLD: .{tld}')

    # 7. URL structural features
    if features['length'] > 100:
        score += 10
        reasons.append('📏 Very long URL (>100 chars)')
    if features['num_at'] > 0:
        score += 20
        reasons.append('⚠️ "@" symbol in URL (redirect trick)')
    if features['has_port']:
        score += 15
        reasons.append('⚠️ Non-standard port in URL')
    if features['encoded_chars'] > 5:
        score += 10
        reasons.append('⚠️ Excessive URL encoding')
    if features['subdomain_count'] >= 3:
        score += 15
        reasons.append(f'⚠️ {features["subdomain_count"]} subdomain levels')
    if features['num_hyphens'] >= 4:
        score += 10
        reasons.append('⚠️ Many hyphens in domain')

    # 8. IP address as hostname
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        score += 25
        reasons.append('🚨 IP address used as hostname')

    # 9. Regex pattern checks
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url):
            score += 8
            break

    # 10. URL shortener
    if check_url_shortener(domain):
        score += 20
        reasons.append('🔗 URL shortener (hides real destination)')

    # 11. Redirect chain
    if len(redirect_chain) > 3:
        score += 15
        reasons.append(f'🔄 {len(redirect_chain)-1} redirects detected')
    final_domain = ''
    if redirect_chain:
        final_parsed = urlparse(redirect_chain[-1]['url'])
        final_domain = final_parsed.netloc
        if final_domain and final_domain != domain:
            score += 10
            reasons.append(f'🔄 Redirects to different domain: {final_domain}')

    # 12. No MX records
    if not dns_records.get('MX'):
        score += 10
        reasons.append('❌ No MX records (not a real mail domain)')

    # 13. No SPF / DMARC
    if not spf:
        score += 5
        reasons.append('⚠️ No SPF record')
    if not dmarc:
        score += 5
        reasons.append('⚠️ No DMARC record')

    # 14. Homograph / IDN
    if check_homograph(domain):
        score += 25
        reasons.append('🔤 IDN/homograph attack detected')

    # 15. DGA detection
    if check_dga(domain):
        score += 20
        reasons.append('🤖 DGA-style domain (algorithmically generated)')

    score = min(score, 100)

    if score < 25:
        risk = '✅ SAFE'
        risk_level = 'safe'
    elif score < 50:
        risk = '⚠️ SUSPICIOUS'
        risk_level = 'suspicious'
    elif score < 75:
        risk = '🚨 LIKELY PHISHING'
        risk_level = 'phishing'
    else:
        risk = '💀 CONFIRMED DANGER'
        risk_level = 'danger'

    return score, risk, risk_level, reasons


# ── Main scan route ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json or {}
    url = data.get('url', '').strip()

    if not url.startswith('http'):
        return jsonify({'error': 'URL must start with http:// or https://'})

    url = unquote(url)
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    domain = domain.split(':')[0]  # strip port

    # Resolve IP
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = 'Unresolvable'

    # Parallel data collection
    with ThreadPoolExecutor(max_workers=6) as ex:
        f_age       = ex.submit(get_domain_age, domain)
        f_ssl       = ex.submit(check_ssl_cert, domain)
        f_redirect  = ex.submit(check_redirect_chain, url)
        f_dns       = ex.submit(check_dns_records, domain)
        f_spf       = ex.submit(check_spf_dkim, domain)

    age            = f_age.result()
    ssl_info       = f_ssl.result()
    redirect_chain = f_redirect.result()
    dns_records    = f_dns.result()
    spf, dmarc     = f_spf.result()
    features       = url_features(url, domain)
    impersonated   = check_brand_impersonation(domain, url)
    is_shortener   = check_url_shortener(domain)
    is_homograph   = check_homograph(domain)
    is_dga         = check_dga(domain)

    score, risk, risk_level, reasons = compute_score(
        url, domain, age, ssl_info, redirect_chain,
        dns_records, spf, dmarc, features
    )

    return jsonify({
        'score': score,
        'risk': risk,
        'risk_level': risk_level,
        'domain': domain,
        'ip': ip,
        'age_days': age,
        'reasons': reasons,
        'ssl': ssl_info,
        'redirect_chain': redirect_chain,
        'dns': dns_records,
        'spf': spf,
        'dmarc': dmarc,
        'features': features,
        'impersonated_brands': impersonated,
        'is_shortener': is_shortener,
        'is_homograph': is_homograph,
        'is_dga': is_dga,
        'scanned_at': datetime.utcnow().isoformat() + 'Z',
    })


# ── CLI mode ───────────────────────────────────────────────────────────────────

def cli_scan(url):
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  PhishScan Pro  |  Scanning: {url}")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    domain = domain.split(':')[0]

    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = 'Unresolvable'

    print(f"{Fore.YELLOW}[*] Collecting intelligence (parallel)...{Style.RESET_ALL}")

    with ThreadPoolExecutor(max_workers=6) as ex:
        f_age      = ex.submit(get_domain_age, domain)
        f_ssl      = ex.submit(check_ssl_cert, domain)
        f_redirect = ex.submit(check_redirect_chain, url)
        f_dns      = ex.submit(check_dns_records, domain)
        f_spf      = ex.submit(check_spf_dkim, domain)

    age            = f_age.result()
    ssl_info       = f_ssl.result()
    redirect_chain = f_redirect.result()
    dns_records    = f_dns.result()
    spf, dmarc     = f_spf.result()
    features       = url_features(url, domain)
    impersonated   = check_brand_impersonation(domain, url)

    score, risk, risk_level, reasons = compute_score(
        url, domain, age, ssl_info, redirect_chain,
        dns_records, spf, dmarc, features
    )

    color = Fore.GREEN if risk_level == 'safe' else \
            Fore.YELLOW if risk_level == 'suspicious' else \
            Fore.RED

    print(f"  Domain   : {domain}")
    print(f"  IP       : {ip}")
    print(f"  Age      : {age if age >= 0 else 'Unknown'} days")
    print(f"  SSL      : {'Valid' if ssl_info['valid'] else 'INVALID'} | Issuer: {ssl_info['issuer']} | Expires: {ssl_info['expiry']}")
    print(f"  SPF      : {'✓' if spf else '✗'}  DMARC: {'✓' if dmarc else '✗'}")
    print(f"  Shortener: {'Yes' if check_url_shortener(domain) else 'No'}")
    print(f"  Homograph: {'Yes' if check_homograph(domain) else 'No'}")
    print(f"  DGA      : {'Yes' if check_dga(domain) else 'No'}")
    if impersonated:
        print(f"  Brands   : {', '.join(impersonated)}")
    print()

    if reasons:
        print(f"{Fore.YELLOW}[!] Risk factors:{Style.RESET_ALL}")
        for r in reasons:
            print(f"    {r}")

    print(f"\n{color}{'─'*40}")
    print(f"  SCORE: {score}/100   VERDICT: {risk}")
    print(f"{'─'*40}{Style.RESET_ALL}\n")

    if redirect_chain:
        print(f"{Fore.CYAN}[→] Redirect chain:{Style.RESET_ALL}")
        for step in redirect_chain:
            print(f"    [{step['code']}] {step['url']}")
        print()


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        # CLI mode
        target = sys.argv[1]
        if not target.startswith('http'):
            target = 'http://' + target
        cli_scan(target)
    else:
        # Web server mode
        print(f"\n{Fore.GREEN}{'='*50}")
        print("  PhishScan Pro  |  Web Interface")
        print(f"  http://127.0.0.1:5000")
        print(f"{'='*50}{Style.RESET_ALL}\n")
        app.run(host='0.0.0.0', port=5000, debug=False)
