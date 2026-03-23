#!/var/ossec/framework/python/bin/python3
import json
import sys
import os
import base64
import time
import requests
from socket import AF_UNIX, SOCK_DGRAM, socket

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'
CACHE_FILE = f'{pwd}/logs/vt-url-cache.json'

VT_API_URL = "https://www.virustotal.com/api/v3/urls"
MALICIOUS_THRESHOLD = 1
CACHE_TTL = 3600

# Domaines safe a ne jamais verifier sur VT
WHITELIST_DOMAINS = [
    'microsoft.com', 'windowsupdate.com', 'windows.com', 'windows.net',
    'msftconnecttest.com', 'msedge.net', 'office.com', 'office365.com',
    'live.com', 'bing.com', 'msn.com', 'outlook.com', 'skype.com',
    'azure.com', 'azureedge.net', 'azurefd.net', 'gfx.ms', 'sfx.ms',
    'msftstatic.com', 'msftauth.net', 'msauth.net', 'onedrive.com',
    'google.com', 'googleapis.com', 'gstatic.com', 'youtube.com',
    'apple.com', 'icloud.com',
    'digicert.com', 'verisign.com', 'letsencrypt.org', 'globalsign.com',
    'symantec.com', 'sectigo.com', 'usertrust.com', 'comodoca.com',
    'cloudflare.com', 'cloudflare-dns.com',
    'akamai.com', 'akamaized.net', 'akadns.net',
    'amazonaws.com', 'cloudfront.net',
    'facebook.com', 'fbcdn.net',
    'mozilla.org', 'mozilla.com',
    'nelreports.net', 'trafficmanager.net',
]

def is_whitelisted(hostname):
    hostname = hostname.lower()
    for domain in WHITELIST_DOMAINS:
        if hostname == domain or hostname.endswith('.' + domain):
            return True
    return False

def log(msg):
    with open(LOG_FILE, 'a') as f:
        f.write(msg + '\n')

def send_msg(msg, agent):
    if not agent or agent.get('id') == '000':
        string = '1:virustotal:{0}'.format(json.dumps(msg))
    else:
        location = '[{0}] ({1}) {2}'.format(
            agent['id'], agent['name'], agent.get('ip', 'any')
        )
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->virustotal:{1}'.format(location, json.dumps(msg))
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except Exception as e:
        log(f'# custom-virustotal-url: socket error: {e}')

def load_cache():
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def save_cache(cache):
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except Exception:
        pass

def main(args):
    if len(args) < 3:
        sys.exit(1)

    alert_file = args[1]
    apikey = args[2]

    try:
        with open(alert_file) as f:
            alert = json.load(f)
    except Exception:
        sys.exit(1)

    data = alert.get('data', {})
    event_type = data.get('event_type', '')
    full_url = ''
    hostname = ''

    if event_type == 'http':
        hostname = data.get('http', {}).get('hostname', '')
        url_path = data.get('http', {}).get('url', '')
        if hostname:
            full_url = f'http://{hostname}{url_path}'
    elif event_type == 'tls':
        hostname = data.get('tls', {}).get('sni', '')
        if hostname:
            full_url = f'https://{hostname}/'

    if not full_url or not hostname:
        sys.exit(0)

    # Skip whitelisted domains
    if is_whitelisted(hostname):
        log(f'# custom-virustotal-url: SKIP whitelisted {hostname}')
        sys.exit(0)

    # Cache lookup
    cache = load_cache()
    now = time.time()
    cache = {k: v for k, v in cache.items() if now - v.get('ts', 0) < CACHE_TTL}

    if hostname in cache:
        cached = cache[hostname]
        log(f'# custom-virustotal-url: CACHE HIT {hostname} malicious={cached.get("malicious", 0)}')
        if cached.get('malicious', 0) >= MALICIOUS_THRESHOLD:
            alert_output = {
                'integration': 'virustotal',
                'virustotal': {
                    'url': full_url,
                    'malicious': cached['malicious'],
                    'positives': cached['malicious'],
                    'suspicious': cached.get('suspicious', 0),
                    'total': cached.get('total', 0),
                    'found': 1,
                    'permalink': cached.get('permalink', ''),
                    'source': {
                        'alert_id': alert.get('id', ''),
                        'agent': alert.get('agent', {}).get('name', ''),
                        'file': hostname,
                    }
                }
            }
            send_msg(alert_output, alert.get('agent'))
        sys.exit(0)

    log(f'# custom-virustotal-url: Checking {full_url}')

    url_id = base64.urlsafe_b64encode(full_url.encode()).decode().rstrip('=')
    headers = {'x-apikey': apikey, 'Accept': 'application/json'}

    try:
        response = requests.get(f'{VT_API_URL}/{url_id}', headers=headers, timeout=30)

        if response.status_code == 404:
            scan_resp = requests.post(VT_API_URL, headers=headers, data={'url': full_url}, timeout=30)
            if scan_resp.status_code == 200:
                time.sleep(15)
                response = requests.get(f'{VT_API_URL}/{url_id}', headers=headers, timeout=30)
            else:
                sys.exit(0)

        if response.status_code == 429:
            log(f'# custom-virustotal-url: rate limited (429)')
            sys.exit(0)

        if response.status_code != 200:
            log(f'# custom-virustotal-url: VT returned {response.status_code}')
            sys.exit(0)

        vt_data = response.json()
        stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values()) if stats else 0
        permalink = f'https://www.virustotal.com/gui/url/{url_id}'

        cache[hostname] = {
            'malicious': malicious_count,
            'suspicious': suspicious,
            'total': total,
            'permalink': permalink,
            'ts': now,
        }
        save_cache(cache)

        log(f'# custom-virustotal-url: {hostname} malicious={malicious_count}/{total}')

        alert_output = {
            'integration': 'virustotal',
            'virustotal': {
                'url': full_url,
                'malicious': malicious_count,
                'positives': malicious_count,
                'suspicious': suspicious,
                'total': total,
                'found': 1 if malicious_count >= MALICIOUS_THRESHOLD else 0,
                'permalink': permalink,
                'source': {
                    'alert_id': alert.get('id', ''),
                    'agent': alert.get('agent', {}).get('name', ''),
                    'file': hostname,
                }
            }
        }
        send_msg(alert_output, alert.get('agent'))

    except Exception as e:
        log(f'# custom-virustotal-url: error: {e}')
        sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)