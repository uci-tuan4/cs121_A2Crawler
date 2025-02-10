from configparser import ConfigParser
from argparse import ArgumentParser

from utils.server_registration import get_cache_server
from utils.config import Config
from crawler import Crawler

import scraper


def main(config_file, restart):
    cparser = ConfigParser()
    cparser.read(config_file)
    config = Config(cparser)
    config.cache_server = get_cache_server(config, restart)
    crawler = Crawler(config, restart)
    crawler.start()


def print_top_50_frequencies(freqs):
    sorted_frequencies = sorted(
        freqs.items(),
        key=lambda x: (-x[1], x[0])
    )
    print("Top 50 most common words:")
    for word, freq in sorted_frequencies[:50]:
        print(f"{word} -> {freq}")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--restart", action="store_true", default=False)
    parser.add_argument("--config_file", type=str, default="config.ini")
    args = parser.parse_args()
    main(args.config_file, args.restart)

    print(f"Total unique pages found: {len(scraper.unique_urls)}")
    print(f"The longest page is {scraper.longest_page_url} with {scraper.max_word_count} words.")
    print_top_50_frequencies(scraper.word_frequencies)
    sorted_subdomains = sorted(scraper.subdomain_counts.items())
    print(f"Total subdomains found in 'ics.uci.edu': {len(sorted_subdomains)}")
    for subdomain, count in sorted_subdomains:
        print(f"https://{subdomain}, {count}")
