from __future__ import annotations
 
import csv
import io
import os
import re
import socket
import ssl
import time
import zipfile
from datetime import datetime, timezone
from functools import lru_cache
from ipaddress import ip_address
from urllib.parse import urljoin, urlparse
 
import requests
import tldextract
from bs4 import BeautifulSoup
 
FEATURE_NAMES = [
    'having_IPhaving_IP_Address',
    'URLURL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'SSLfinal_State',
    'Domain_registeration_length',
    'Favicon',
    'port',
    'HTTPS_token',
    'Request_URL',
    'URL_of_Anchor',
    'Links_in_tags',
    'SFH',
    'Submitting_to_email',
    'Abnormal_URL',
    'Redirect',
    'on_mouseover',
    'RightClick',
    'popUpWidnow',
    'Iframe',
    'age_of_domain',
    'DNSRecord',
    'web_traffic',
    'Page_Rank',
    'Google_Index',
    'Links_pointing_to_page',
    'Statistical_report',
]
 
TIMEOUT = 6
UA = {'User-Agent': 'Mozilla/5.0'}
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline bundled suffix list
 
 
def registered_domain(host: str | None) -> str | None:
  if not host:
    return None
  ext = _EXTRACT(host)
  return ext.registered_domain or host
 
 
# ---------------------------------------------------------------- RDAP (WHOIS)
@lru_cache(maxsize=2048)
def _rdap_dates(domain: str) -> tuple[datetime | None, datetime | None]:
  """Return (registration_date, expiration_date) from RDAP, or (None, None)."""
  try:
    r = requests.get(
        f'https://rdap.org/domain/{domain}', timeout=TIMEOUT, headers=UA
    )
    if r.status_code != 200:
      return None, None
    registered = expires = None
    for ev in r.json().get('events', []):
      when = datetime.fromisoformat(ev['eventDate'].replace('Z', '+00:00'))
      if ev.get('eventAction') == 'registration':
        registered = when
      elif ev.get('eventAction') == 'expiration':
        expires = when
    return registered, expires
  except Exception:
    return None, None
 
 
# ---------------------------------------------------------------- Tranco rank
_TRANCO: dict[str, int] | None = None
 
 
def _load_tranco() -> dict[str, int]:
  global _TRANCO
  if _TRANCO is not None:
    return _TRANCO
  ranks: dict[str, int] = {}
  try:
    path = os.environ.get('TRANCO_CSV')
    if path and os.path.exists(path):
      text = open(path, encoding='utf-8').read()
    else:
      raw = requests.get(
          'https://tranco-list.eu/top-1m.csv.zip', timeout=60
      ).content
      with zipfile.ZipFile(io.BytesIO(raw)) as z:
        text = z.read(z.namelist()[0]).decode('utf-8')
    for rank, domain in csv.reader(io.StringIO(text)):
      ranks[domain] = int(rank)
  except Exception:
    ranks = {}
  _TRANCO = ranks
  return ranks
 
 
def _rank(hostname) -> int | None:
  ranks = _load_tranco()
  if not ranks:
    return None
  return ranks.get(registered_domain(hostname) or '', 0)
 
 
# ------------------------------------------------------------------ Google index
@lru_cache(maxsize=2048)
def _google_indexed(domain: str) -> bool | None:
  key, cx = os.environ.get('GOOGLE_API_KEY'), os.environ.get('GOOGLE_CSE_ID')
  if not (key and cx):
    return None
  try:
    r = requests.get(
        'https://www.googleapis.com/customsearch/v1',
        params={'key': key, 'cx': cx, 'q': f'site:{domain}', 'num': 1},
        timeout=TIMEOUT,
    )
    return int(r.json()['searchInformation']['totalResults']) > 0
  except Exception:
    return None
 
 
# ------------------------------------------------------- Statistical report feeds
_FEEDS = [
    'https://openphish.com/feed.txt',
    'https://urlhaus.abuse.ch/downloads/text_online/',
]
_BAD_HOSTS: set[str] = set()
_BAD_LOADED_AT = 0.0
 
 
def _refresh_feeds(max_age: int = 3600) -> bool:
  global _BAD_HOSTS, _BAD_LOADED_AT
  if _BAD_HOSTS and time.time() - _BAD_LOADED_AT < max_age:
    return True
  hosts: set[str] = set()
  for feed in _FEEDS:
    try:
      text = requests.get(feed, timeout=TIMEOUT, headers=UA).text
      for line in text.splitlines():
        host = urlparse(line.strip()).hostname
        if host:
          hosts.add(host.lower())
    except Exception:
      continue
  if hosts:
    _BAD_HOSTS, _BAD_LOADED_AT = hosts, time.time()
    return True
  return bool(_BAD_HOSTS)
 
 
# =========================================================
# FEATURE EXTRACTION FUNCTIONS (1 - 30)
# =========================================================
 
# 1. IP Address
def has_ip_address(hostname):
  try:
    ip_address(hostname)
    return -1
  except ValueError:
    return 1
 
 
# 2. URL Length
def url_length(url):
  length = len(url)
  if length < 54:
    return 1
  elif length <= 75:
    return 0
  else:
    return -1
 
 
# 3. Shortening Service
def shortening_service(url):
  shortening_domains = [
      'bit.ly',
      'tinyurl.com',
      'goo.gl',
      't.co',
      'is.gd',
      'cli.gs',
      'ow.ly',
      'buff.ly',
      'adf.ly',
      'bit.do',
      'cutt.ly',
      'shorturl.at',
      'rb.gy',
      'tiny.cc',
  ]
  hostname = urlparse(url).hostname
  if hostname:
    hostname = hostname.lower()
    for domain in shortening_domains:
      if hostname == domain or hostname.endswith('.' + domain):
        return -1
  return 1
 
 
# 4. At Symbol
def at_symbol(url):
  return -1 if '@' in url else 1
 
 
# 5. Double Slash Redirecting
def double_slash_redirecting(url):
  temp = re.sub(r'^https?:\/\/', '', url.lower())
  return -1 if '//' in temp else 1
 
 
# 6. Prefix / Suffix
def prefix_suffix(hostname):
  if hostname is None:
    return -1
  return -1 if '-' in hostname else 1
 
 
# 7. Sub Domain
def sub_domain(hostname):
  if hostname is None:
    return -1
  parts = hostname.split('.')
  if len(parts) <= 2:
    return 1
  elif len(parts) == 3:
    return 0
  else:
    return -1
 
 
# 8. SSL Final State
def ssl_final_state(url):
  parsed = urlparse(url)
  if parsed.scheme != 'https':
    return -1
  hostname = parsed.hostname
  if hostname is None:
    return -1
  try:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=5) as sock:
      with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        cert = ssock.getpeercert()
        if cert:
          return 1
  except Exception:
    pass
  return -1
 
 
# 9. Domain Registration Length
def domain_registration_length(hostname):
  _, expires = _rdap_dates(registered_domain(hostname) or '')
  if expires is None:
    return 0
  days = (expires - datetime.now(timezone.utc)).days
  return -1 if days <= 365 else 1
 
 
# 10. Favicon
def favicon(url, soup):
  if soup is None:
    return -1
  hostname = urlparse(url).hostname
  if hostname is None:
    return -1
  icons = soup.find_all(
      'link',
      rel=lambda value: value and any('icon' in str(x).lower() for x in value),
  )
  if not icons:
    return 1
  for icon in icons:
    href = icon.get('href')
    if not href:
      continue
    icon_url = urljoin(url, href)
    icon_host = urlparse(icon_url).hostname
    if icon_host and icon_host != hostname:
      return -1
  return 1
 
 
# 11. Port
def port_feature(url):
  parsed = urlparse(url)
  try:
    port = parsed.port
  except Exception:
    return -1
  if port is None:
    return 1
  if port in [80, 443]:
    return 1
  return -1
 
 
# 12. HTTPS Token
def https_token(url):
  hostname = urlparse(url).hostname
  if hostname is None:
    return -1
  hostname = hostname.lower()
  if 'https' in hostname:
    return -1
  return 1
 
 
# 13. Request URL
def request_url(url, soup):
  if soup is None:
    return -1
  hostname = urlparse(url).hostname
  if hostname is None:
    return -1
  resources = []
  for tag in soup.find_all('img'):
    if tag.get('src'):
      resources.append(tag.get('src'))
  for tag in soup.find_all('script'):
    if tag.get('src'):
      resources.append(tag.get('src'))
  for tag in soup.find_all('link'):
    if tag.get('href'):
      resources.append(tag.get('href'))
  if not resources:
    return 1
  external = 0
  for resource in resources:
    absolute = urljoin(url, resource)
    resource_host = urlparse(absolute).hostname
    if resource_host and resource_host != hostname:
      external += 1
  ratio = external / len(resources)
  if ratio < 0.22:
    return 1
  elif ratio <= 0.61:
    return 0
  else:
    return -1
 
 
# 14. URL of Anchor
def url_of_anchor(url, soup):
  if soup is None:
    return -1
  hostname = urlparse(url).hostname
  anchors = soup.find_all('a', href=True)
  if not anchors:
    return 1
  external = 0
  valid = 0
  for a in anchors:
    href = a.get('href')
    if href.startswith('#'):
      continue
    absolute = urljoin(url, href)
    anchor_host = urlparse(absolute).hostname
    if anchor_host:
      valid += 1
      if anchor_host != hostname:
        external += 1
  if valid == 0:
    return 1
  ratio = external / valid
  if ratio < 0.31:
    return 1
  elif ratio <= 0.67:
    return 0
  else:
    return -1
 
 
# 15. Links in tags
def links_in_tags(url, soup):
  if soup is None:
    return -1
  hostname = urlparse(url).hostname
  tags = []
  tags.extend(soup.find_all('link', href=True))
  tags.extend(soup.find_all('script', src=True))
  tags.extend(soup.find_all('meta', content=True))
  if not tags:
    return 1
  external = 0
  for tag in tags:
    value = tag.get('href') or tag.get('src') or tag.get('content')
    if not value:
      continue
    absolute = urljoin(url, value)
    tag_host = urlparse(absolute).hostname
    if tag_host and tag_host != hostname:
      external += 1
  ratio = external / len(tags)
  if ratio < 0.17:
    return 1
  elif ratio <= 0.81:
    return 0
  else:
    return -1
 
 
# 16. SFH (Server Form Handler)
def sfh(url, soup):
  if soup is None:
    return -1
  hostname = urlparse(url).hostname
  forms = soup.find_all('form')
  if not forms:
    return 1
  for form in forms:
    action = form.get('action', '').strip()
    if action == '':
      continue
    if action.lower() == 'about:blank':
      return -1
    action_url = urljoin(url, action)
    action_host = urlparse(action_url).hostname
    if action_host and action_host != hostname:
      return 0
  return 1
 
 
# 17. Submitting to email
def submitting_to_email(soup):
  if soup is None:
    return -1
  forms = soup.find_all('form')
  for form in forms:
    action = form.get('action', '').lower()
    if 'mailto:' in action:
      return -1
    if 'mail(' in action:
      return -1
  return 1
 
 
# 18. Abnormal URL
def abnormal_url(url):
  parsed = urlparse(url)
  if not parsed.hostname:
    return -1
  if '.' not in parsed.hostname:
    return -1
  return 1
 
 
# 19. Redirect
# NOTE: the training dataset only contains {0, 1}, where 0 is the common
# value (few redirects) and 1 the rare one (many redirects).
def redirect_feature(response):
  if response is None:
    return 0
  return 0 if len(response.history) <= 1 else 1
 
 
# 20. on_mouseover
def on_mouseover(soup):
  if soup is None:
    return -1
  html = str(soup).lower()
  return -1 if 'onmouseover' in html else 1
 
 
# 21. Right Click
def right_click(soup):
  if soup is None:
    return -1
  html = str(soup).lower()
  patterns = [
      'event.button==2',
      'event.button == 2',
      'contextmenu',
      'disable right click',
      'preventdefault',
  ]
  for pattern in patterns:
    if pattern in html:
      return -1
  return 1
 
 
# 22. PopUp Window
def popup_window(soup):
  if soup is None:
    return -1
  html = str(soup).lower()
  if 'window.open(' in html:
    return -1
  return 1
 
 
# 23. Iframe
def iframe_feature(soup):
  if soup is None:
    return -1
  iframes = soup.find_all('iframe')
  if iframes:
    return -1
  return 1
 
 
# 24. Age of Domain
def age_of_domain(hostname):
  registered, _ = _rdap_dates(registered_domain(hostname) or '')
  if registered is None:
    return 0
  days = (datetime.now(timezone.utc) - registered).days
  return -1 if days < 180 else 1
 
 
# 25. DNS Record
def dns_record(hostname):
  if hostname is None:
    return -1
  try:
    socket.gethostbyname(hostname)
    return 1
  except Exception:
    return -1
 
 
# 26. Web Traffic
def web_traffic(hostname):
  rank = _rank(hostname)
  if rank is None:
    return 0
  if rank == 0:
    return -1
  return 1 if rank < 100_000 else 0
 
 
# 27. Page Rank
def page_rank(hostname):
  key = os.environ.get('OPENPAGERANK_KEY')
  domain = registered_domain(hostname)
  if key and domain:
    try:
      r = requests.get(
          'https://openpagerank.com/api/v1.0/getPageRank',
          params={'domains[]': domain},
          headers={'API-OPR': key},
          timeout=TIMEOUT,
      )
      value = r.json()['response'][0].get('page_rank_decimal')
      if value is not None:
        return -1 if float(value) < 2 else 1
    except Exception:
      pass
  rank = _rank(hostname)
  if rank is None:
    return 0
  return 1 if 0 < rank < 100_000 else -1
 
 
# 28. Google Index
def google_index(url):
  domain = registered_domain(urlparse(url).hostname)
  indexed = _google_indexed(domain) if domain else None
  if indexed is None:
    rank = _rank(urlparse(url).hostname)
    if rank is None:
      return 0
    return 1 if rank > 0 else -1
  return 1 if indexed else -1
 
 
# 29. Links Pointing to Page
def links_pointing_to_page(url):
  return 0
 
 
# 30. Statistical Report
def statistical_report(url):
  if not _refresh_feeds():
    return 0
  host = (urlparse(url).hostname or '').lower()
  return -1 if host in _BAD_HOSTS else 1
 
 
# =========================================================
# MAIN FEATURE EXTRACTION FUNCTION
# =========================================================
 
 
def extract_features(url):
  if not url.startswith(('http://', 'https://')):
    url = 'http://' + url
 
  parsed = urlparse(url)
  hostname = parsed.hostname
 
  response = None
  soup = None
 
  try:
    response = requests.get(
        url,
        timeout=10,
        allow_redirects=True,
        headers={'User-Agent': 'Mozilla/5.0'},
    )
    soup = BeautifulSoup(response.text, 'html.parser')
  except Exception:
    pass
 
  features = [
      has_ip_address(hostname),
      url_length(url),
      shortening_service(url),
      at_symbol(url),
      double_slash_redirecting(url),
      prefix_suffix(hostname),
      sub_domain(hostname),
      ssl_final_state(url),
      domain_registration_length(hostname),
      favicon(url, soup),
      port_feature(url),
      https_token(url),
      request_url(url, soup),
      url_of_anchor(url, soup),
      links_in_tags(url, soup),
      sfh(url, soup),
      submitting_to_email(soup),
      abnormal_url(url),
      redirect_feature(response),
      on_mouseover(soup),
      right_click(soup),
      popup_window(soup),
      iframe_feature(soup),
      age_of_domain(hostname),
      dns_record(hostname),
      web_traffic(hostname),
      page_rank(hostname),
      google_index(url),
      links_pointing_to_page(url),
      statistical_report(url),
  ]
 
  return features
 