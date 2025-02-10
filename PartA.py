import re
import sys


def tokenize(file_path):
    """
    reads inputted file and returns a list of tokens
    O(n) time complexity becaues the reading, regex, and list comprehension make
    n operations where n is the length of the file.

    :param file_path:
    :return:
    """
    tokens = []

    try:
        with open(file_path, 'r') as f:
            text = f.read()
            raw = re.findall(r'\w+', text)
            tokens = [token.lower() for token in raw]

        return tokens

    except FileNotFoundError:
        raise FileNotFoundError('File Not Found')


def computeWordFrequencies(tokens):
    """
    takes a list of tokens and returns a dictionary of tokens and their frequencies
    O(n) time complexity because there is 1 dict lookup and update for each token

    :param tokens:
    :return:
    """
    freq_map = {}

    for token in tokens:
        freq_map[token] = freq_map.get(token, 0) + 1

    return freq_map


def printFreqs(freqs):
    """
    takes a dictionary of frequencies and prints out each token and its frequency,
    sorted by frequency in descending order
    O(nlogn) time complexity relative to the size of freqs because of the sorted call

    :param freqs:
    :return:
    """
    if not freqs:
        print("No words to display")
        return

    sorted_frequencies = sorted(
        freqs.items(),
        key=lambda x: (-x[1], x[0])
    )

    for word, freq in sorted_frequencies:
        print(f"{word} -> {freq}")


def main():
    """
    O(nlogn) time complexity because of the printing

    :return:
    """
    if len(sys.argv) != 2:
        print("Usage: python program.py <file1>")
        sys.exit(1)

    file1 = sys.argv[1]

    tokens = tokenize(file1)
    freqs = computeWordFrequencies(tokens)
    printFreqs(freqs)

