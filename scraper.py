import re
import hashlib
from urllib.parse import urlparse, urljoin, urldefrag
from urllib import robotparser
from bs4 import BeautifulSoup

unique_urls = set()
max_word_count = 0
longest_page_url = ""
word_frequencies = {}
subdomain_counts = {}

visited_simhashes = []

USER_AGENT = "IR UW25 35299222"


class RobotsHandler:
    def __init__(self):
        self.parsers = {}

    def can_fetch(self, user_agent, url):
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain not in self.parsers:
            self._fetch_robots(domain, parsed.scheme)

        rp = self.parsers.get(domain)
        if rp:
            return rp.can_fetch(user_agent, url)
        else:
            return True  # No robots.txt means allow by default

    def _fetch_robots(self, domain, scheme):
        rp = robotparser.RobotFileParser()
        robots_url = f"{scheme}://{domain}/robots.txt"
        rp.set_url(robots_url)
        try:
            rp.read()
            self.parsers[domain] = rp
        except:
            self.parsers[domain] = None


robots_handler = RobotsHandler()
with open('stop_words.txt', 'r') as f:
    stop_words = set(f.read().split())


def scraper(url, resp):
    if not robots_handler.can_fetch(USER_AGENT, url):
        return []

    final_url = resp.url
    final_url, _ = urldefrag(final_url)

    if final_url not in unique_urls:
        unique_urls.add(final_url)

        # If the URL is in 'ics.uci.edu' domain, update subdomain counts
        parsed = urlparse(final_url)
        if 'ics.uci.edu' in parsed.netloc:
            subdomain = parsed.netloc.lower()
            subdomain_counts[subdomain] = subdomain_counts.get(subdomain, 0) + 1

    links = extract_next_links(final_url, resp)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    global max_word_count, longest_page_url

    # Return a list with the hyperlinks (as strings) scraped from resp.raw_response.content
    links = []

    '''
    content_length = resp.raw_response.headers.get('Content-Length')
    MAX_CONTENT_LENGTH = 1024 * 1024 * 2  # 2 MB limit

    if content_length and int(content_length) < MAX_CONTENT_LENGTH:
        return links
    '''

    if not resp.raw_response or resp.status != 200:
        return links

    # Check if the content type is HTML
    content_type = resp.raw_response.headers.get('Content-Type', '')
    if 'text/html' not in content_type:
        return links

    try:
        # Parse the page content using BeautifulSoup
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

        if is_similar_content(soup):
            return links  # Skip near-duplicate pages

        texts = soup.get_text()
        tokens = tokenize_text(texts)

        # Update the max word count and URL if necessary
        word_count = len(tokens)
        if word_count > max_word_count:
            max_word_count = word_count
            longest_page_url = url

        for token in tokens:
            if token not in stop_words:
                word_frequencies[token] = word_frequencies.get(token, 0) + 1

        # Extract all anchor tags with href attributes
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            # Resolve relative URLs
            href = urljoin(url, href)
            # Remove fragment from URL
            href, _ = urldefrag(href)
            links.append(href)
    except Exception as e:
        print(f"Error processing {url}: {e}")
        return links

    return links


def has_high_text_content(soup):
    texts = soup.get_text()
    words = texts.split()
    num_words = len(words)
    MIN_WORDS = 200  # Adjust this threshold as needed
    return num_words >= MIN_WORDS


def is_valid(url):
    # Decide whether to crawl this url or not
    try:
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return False

        allowed_domains = (
            "ics.uci.edu",
            "cs.uci.edu",
            "informatics.uci.edu",
            "stat.uci.edu"
        )

        allowed_domains_suffix = (
            ".ics.uci.edu",
            ".cs.uci.edu",
            ".informatics.uci.edu",
            ".stat.uci.edu"
        )

        if not any(parsed.netloc == domain for domain in allowed_domains) and not any(parsed.netloc.endswith(domain_suffix) for domain_suffix in allowed_domains_suffix):
            return False

        # Skips individual commits in gitlab.ics.uci.edu
        if '/commit/' in parsed.path or '/commits/' in parsed.path or '/tree/' in parsed.path:
            return False

        # Check for infinite traps in query parameters (e.g., session IDs, calendars)
        trap_patterns = [
            r'(.+/)+.*(\1)+.*',  # Repeated directories
            r'(\?|\&)(.+)\=(.+)\&\2\=\3',  # Repeated query parameters
            r'.*calendar.*',  # URLs containing 'calendar'
            r'.*?\d{4}/\d{2}/\d{2}.*',  # URLs with dates
        ]

        for pattern in trap_patterns:
            if re.search(pattern, url):
                return False

        # Exclude URLs with disallowed file extensions
        if re.match(
                r".*\.(css|js|bmp|gif|jpe?g|ico"
                r"|png|tiff?|mid|mp2|mp3|mp4|apk|war|img|sql"
                r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
                r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
                r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
                r"|epub|dll|cnf|tgz|sha1|git|ppsx"
                r"|thmx|mso|arff|rtf|jar|csv|java"
                r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()):
            return False

        return True
    except TypeError:
        print("TypeError for", parsed)
        raise


def tokenize_text(text):
    # Use the provided tokenize function on the text content
    raw = re.findall(r'\w+', text)
    tokens = [token.lower() for token in raw]
    return tokens


# SimHash implementation
def hash_token(token):
    hash_object = hashlib.sha1(token.encode('utf-8'))
    digest = hash_object.digest()
    # Use first 8 bytes to get 64 bits
    return int.from_bytes(digest[:8], byteorder='big')


def simhash(tokens, hashbits=64):
    v = [0] * hashbits

    for token in tokens:
        h = hash_token(token)
        for i in range(hashbits):
            bitmask = 1 << i
            if h & bitmask:
                v[i] += 1
            else:
                v[i] -= 1

    fingerprint = 0
    for i in range(hashbits):
        if v[i] > 0:
            fingerprint |= 1 << i
        # If v[i] == 0, bit stays 0
    return fingerprint


def hamming_distance(x, y):
    return bin(x ^ y).count('1')


def is_similar_content(soup, threshold=3):
    text = soup.get_text()
    tokens = text.split()

    tokens = [token.lower() for token in tokens if token.isalpha()]

    sim_hash = simhash(tokens)

    for existing_simhash in visited_simhashes:
        distance = hamming_distance(sim_hash, existing_simhash)
        if distance <= threshold:
            return True  # Near-duplicate page found

    # No near-duplicate found; add the simhash to the list
    visited_simhashes.append(sim_hash)
    return False
