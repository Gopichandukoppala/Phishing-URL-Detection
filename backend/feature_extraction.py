import re
import socket
import ssl
import requests
import ipaddress
from urllib.parse import urlparse, urljoin
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
    'Statistical_report'
]


# ---------------------------------------------------------
# 1. Check whether hostname is an IP address
# ---------------------------------------------------------

def has_ip_address(hostname):

    try:
        ipaddress.ip_address(hostname)
        return -1
    except ValueError:
        return 1


# ---------------------------------------------------------
# 2. URL length
# ---------------------------------------------------------

def url_length(url):

    length = len(url)

    if length < 54:
        return 1
    elif length <= 75:
        return 0
    else:
        return -1


# ---------------------------------------------------------
# 3. URL shortening service
# ---------------------------------------------------------

def shortening_service(url):

    shortening_domains = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "is.gd",
        "cli.gs",
        "ow.ly",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "cutt.ly",
        "shorturl.at",
        "rb.gy",
        "tiny.cc"
    ]

    hostname = urlparse(url).hostname

    if hostname:
        hostname = hostname.lower()

        for domain in shortening_domains:
            if hostname == domain or hostname.endswith("." + domain):
                return -1

    return 1


# ---------------------------------------------------------
# 4. @ symbol
# ---------------------------------------------------------

def at_symbol(url):

    return -1 if "@" in url else 1


# ---------------------------------------------------------
# 5. Double slash redirecting
# ---------------------------------------------------------

def double_slash_redirecting(url):

    # Ignore the // in http:// and https://

    temp = re.sub(r'^https?:\/\/', '', url.lower())

    return -1 if "//" in temp else 1


# ---------------------------------------------------------
# 6. Prefix / suffix
# ---------------------------------------------------------

def prefix_suffix(hostname):

    if hostname is None:
        return -1

    return -1 if "-" in hostname else 1


# ---------------------------------------------------------
# 7. Subdomain
# ---------------------------------------------------------

def sub_domain(hostname):

    if hostname is None:
        return -1

    parts = hostname.split(".")

    # Simple approximation:
    # example.com -> 2 parts
    # www.example.com -> 3 parts

    if len(parts) <= 2:
        return 1

    elif len(parts) == 3:
        return 0

    else:
        return -1


# ---------------------------------------------------------
# 8. SSL final state
# ---------------------------------------------------------

def ssl_final_state(url):

    parsed = urlparse(url)

    if parsed.scheme != "https":
        return -1

    hostname = parsed.hostname

    if hostname is None:
        return -1

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as ssock:

                cert = ssock.getpeercert()

                if cert:
                    return 1

    except Exception:
        pass

    return -1


# ---------------------------------------------------------
# 9. Domain registration length
#
# Requires WHOIS.
# Placeholder until WHOIS is connected.
# ---------------------------------------------------------

def domain_registration_length(hostname):

    # Cannot reliably obtain registration period
    # from URL alone.

    return -1


# ---------------------------------------------------------
# 10. Favicon
# ---------------------------------------------------------

def favicon(url, soup):

    if soup is None:
        return -1

    hostname = urlparse(url).hostname

    if hostname is None:
        return -1

    icons = soup.find_all(
        "link",
        rel=lambda value:
        value and any(
            "icon" in str(x).lower()
            for x in value
        )
    )

    if not icons:
        return 1

    for icon in icons:

        href = icon.get("href")

        if not href:
            continue

        icon_url = urljoin(url, href)

        icon_host = urlparse(icon_url).hostname

        if icon_host and icon_host != hostname:
            return -1

    return 1


# ---------------------------------------------------------
# 11. Port
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# 12. HTTPS token
# ---------------------------------------------------------

def https_token(url):

    hostname = urlparse(url).hostname

    if hostname is None:
        return -1

    hostname = hostname.lower()

    # HTTPS appearing inside domain name is suspicious
    if "https" in hostname:
        return -1

    return 1


# ---------------------------------------------------------
# 13. Request URL
#
# Percentage of external resources.
# ---------------------------------------------------------

def request_url(url, soup):

    if soup is None:
        return -1

    hostname = urlparse(url).hostname

    if hostname is None:
        return -1

    resources = []

    # Images
    for tag in soup.find_all("img"):
        if tag.get("src"):
            resources.append(tag.get("src"))

    # Scripts
    for tag in soup.find_all("script"):
        if tag.get("src"):
            resources.append(tag.get("src"))

    # CSS
    for tag in soup.find_all("link"):
        if tag.get("href"):
            resources.append(tag.get("href"))

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


# ---------------------------------------------------------
# 14. URL of Anchor
# ---------------------------------------------------------

def url_of_anchor(url, soup):

    if soup is None:
        return -1

    hostname = urlparse(url).hostname

    anchors = soup.find_all("a", href=True)

    if not anchors:
        return 1

    external = 0
    valid = 0

    for a in anchors:

        href = a.get("href")

        if href.startswith("#"):
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


# ---------------------------------------------------------
# 15. Links in tags
# ---------------------------------------------------------

def links_in_tags(url, soup):

    if soup is None:
        return -1

    hostname = urlparse(url).hostname

    tags = []

    tags.extend(soup.find_all("link", href=True))
    tags.extend(soup.find_all("script", src=True))
    tags.extend(soup.find_all("meta", content=True))

    if not tags:
        return 1

    external = 0

    for tag in tags:

        value = (
            tag.get("href")
            or tag.get("src")
            or tag.get("content")
        )

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


# ---------------------------------------------------------
# 16. SFH - Server Form Handler
# ---------------------------------------------------------

def sfh(url, soup):

    if soup is None:
        return -1

    hostname = urlparse(url).hostname

    forms = soup.find_all("form")

    if not forms:
        return 1

    for form in forms:

        action = form.get("action", "").strip()

        if action == "":
            continue

        if action.lower() == "about:blank":
            return -1

        action_url = urljoin(url, action)

        action_host = urlparse(action_url).hostname

        if action_host and action_host != hostname:
            return 0

    return 1


# ---------------------------------------------------------
# 17. Submitting to email
# ---------------------------------------------------------

def submitting_to_email(soup):

    if soup is None:
        return -1

    forms = soup.find_all("form")

    for form in forms:

        action = form.get("action", "").lower()

        if "mailto:" in action:
            return -1

        if "mail(" in action:
            return -1

    return 1


# ---------------------------------------------------------
# 18. Abnormal URL
# ---------------------------------------------------------

def abnormal_url(url):

    parsed = urlparse(url)

    if not parsed.hostname:
        return -1

    # URL must contain a proper hostname
    if "." not in parsed.hostname:
        return -1

    return 1


# ---------------------------------------------------------
# 19. Redirect
# ---------------------------------------------------------

def redirect_feature(response):

    if response is None:
        return -1

    redirects = len(response.history)

    if redirects == 0:
        return 1

    elif redirects == 1:
        return 0

    else:
        return -1


# ---------------------------------------------------------
# 20. on_mouseover
# ---------------------------------------------------------

def on_mouseover(soup):

    if soup is None:
        return -1

    html = str(soup).lower()

    return -1 if "onmouseover" in html else 1


# ---------------------------------------------------------
# 21. RightClick
# ---------------------------------------------------------

def right_click(soup):

    if soup is None:
        return -1

    html = str(soup).lower()

    patterns = [
        "event.button==2",
        "event.button == 2",
        "contextmenu",
        "disable right click",
        "preventdefault"
    ]

    for pattern in patterns:

        if pattern in html:
            return -1

    return 1


# ---------------------------------------------------------
# 22. PopUp Window
# ---------------------------------------------------------

def popup_window(soup):

    if soup is None:
        return -1

    html = str(soup).lower()

    if "window.open(" in html:
        return -1

    return 1


# ---------------------------------------------------------
# 23. Iframe
# ---------------------------------------------------------

def iframe_feature(soup):

    if soup is None:
        return -1

    iframes = soup.find_all("iframe")

    if iframes:
        return -1

    return 1


# ---------------------------------------------------------
# 24. Age of domain
#
# Requires WHOIS.
# ---------------------------------------------------------

def age_of_domain(hostname):

    # Cannot reliably determine from URL alone.
    return -1


# ---------------------------------------------------------
# 25. DNS Record
# ---------------------------------------------------------

def dns_record(hostname):

    if hostname is None:
        return -1

    try:

        socket.gethostbyname(hostname)

        return 1

    except Exception:

        return -1


# ---------------------------------------------------------
# 26. Web traffic
#
# Requires an external traffic-ranking service.
# ---------------------------------------------------------

def web_traffic(hostname):

    return -1


# ---------------------------------------------------------
# 27. Page Rank
#
# Requires external ranking data.
# ---------------------------------------------------------

def page_rank(hostname):

    return -1


# ---------------------------------------------------------
# 28. Google Index
#
# Requires a search/index service.
# ---------------------------------------------------------

def google_index(url):

    return -1


# ---------------------------------------------------------
# 29. Links pointing to page
#
# Requires backlink/search-engine data.
# ---------------------------------------------------------

def links_pointing_to_page(url):

    return -1


# ---------------------------------------------------------
# 30. Statistical report
#
# Requires blacklist/fraud-list data.
# ---------------------------------------------------------

def statistical_report(url):

    return -1


# =========================================================
# MAIN FEATURE EXTRACTION FUNCTION
# =========================================================

def extract_features(url):

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname

    # -----------------------------------------------------
    # Download webpage
    # -----------------------------------------------------

    response = None
    soup = None

    try:

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent":
                "Mozilla/5.0"
            }
        )

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

    except Exception:
        pass

    # -----------------------------------------------------
    # Extract 30 features
    # -----------------------------------------------------

    features = [

        # 1
        has_ip_address(hostname),

        # 2
        url_length(url),

        # 3
        shortening_service(url),

        # 4
        at_symbol(url),

        # 5
        double_slash_redirecting(url),

        # 6
        prefix_suffix(hostname),

        # 7
        sub_domain(hostname),

        # 8
        ssl_final_state(url),

        # 9
        domain_registration_length(hostname),

        # 10
        favicon(url, soup),

        # 11
        port_feature(url),

        # 12
        https_token(url),

        # 13
        request_url(url, soup),

        # 14
        url_of_anchor(url, soup),

        # 15
        links_in_tags(url, soup),

        # 16
        sfh(url, soup),

        # 17
        submitting_to_email(soup),

        # 18
        abnormal_url(url),

        # 19
        redirect_feature(response),

        # 20
        on_mouseover(soup),

        # 21
        right_click(soup),

        # 22
        popup_window(soup),

        # 23
        iframe_feature(soup),

        # 24
        age_of_domain(hostname),

        # 25
        dns_record(hostname),

        # 26
        web_traffic(hostname),

        # 27
        page_rank(hostname),

        # 28
        google_index(url),

        # 29
        links_pointing_to_page(url),

        # 30
        statistical_report(url)
    ]

    return features