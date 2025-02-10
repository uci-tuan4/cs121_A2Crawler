import re
import PartA as A
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup

unique_urls = set()
max_word_count = 0
longest_page_url = ""
word_frequencies = {}
subdomain_counts = {}

with open('stop_words.txt', 'r') as f:
    stop_words = set(f.read().split())


def scraper(url, resp):
    final_url = resp.url
    unique_urls.add(final_url)
    links = extract_next_links(final_url, resp)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    global max_word_count, longest_page_url

    # Return a list with the hyperlinks (as strings) scraped from resp.raw_response.content
    links = []

    # Check if the response status is OK
    if resp.status != 200:
        return links

    content_length = resp.raw_response.headers.get('Content-Length')
    MAX_CONTENT_LENGTH = 1024 * 1024 * 2  # 2 MB limit

    if content_length and int(content_length) < MAX_CONTENT_LENGTH:
        return links

    # Check if the content type is HTML
    content_type = resp.raw_response.headers.get('Content-Type', '')
    if 'text/html' not in content_type:
        return links

    try:
        # Parse the page content using BeautifulSoup
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
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

        if not any(parsed.netloc.endswith(domain) for domain in allowed_domains):
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
                r"|png|tiff?|mid|mp2|mp3|mp4"
                r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
                r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
                r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
                r"|epub|dll|cnf|tgz|sha1"
                r"|thmx|mso|arff|rtf|jar|csv"
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
