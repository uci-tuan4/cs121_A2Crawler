import re
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    # Return a list with the hyperlinks (as strings) scraped from resp.raw_response.content
    links = []

    # Check if the response status is OK
    if resp.status != 200:
        return links

    # Check if the content type is HTML
    content_type = resp.raw_response.headers.get('Content-Type', '')
    if 'text/html' not in content_type:
        return links

    try:
        # Parse the page content using BeautifulSoup
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

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

def is_valid(url):
    # Decide whether to crawl this url or not
    try:
        parsed = urlparse(url)

        if parsed.scheme not in set(["http", "https"]):
            return False

        allowed_domains = (
            "ics.uci.edu",
            "cs.uci.edu",
            "informatics.uci.edu",
            "stat.uci.edu"
        )

        if not any(parsed.netloc.endswith(domain) for domain in allowed_domains):
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