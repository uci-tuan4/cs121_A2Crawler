import PartA as A
import sys


def find_common_tokens(file1_path, file2_path):
    """
    takes two files and returns the common tokens between them
    O(m + n) time complexity where m is the length of file1 and n is the length of file2, because m and n operations
    are performed during tokenization and set conversion, and min(m, n) operations for intersection finding.

    :param file1_path:
    :param file2_path:
    :return:
    """

    try:
        tokens1 = A.tokenize(file1_path)
        tokens2 = A.tokenize(file2_path)

        unique_tokens1 = set(tokens1)
        unique_tokens2 = set(tokens2)

        common_tokens = unique_tokens1.intersection(unique_tokens2)

        '''
        if len(common_tokens) > 0:
            freq1 = A.computeWordFrequencies(tokens1)
            freq2 = A.computeWordFrequencies(tokens2)
            for token in sorted(common_tokens):
                print(f"{token} -> File1: {freq1[token]}, File2: {freq2[token]}")
        '''

        return len(common_tokens)

    except Exception as e:
        print(f"Error processing files: {str(e)}")

    return 0


def main():

    if len(sys.argv) != 3:
        print("Usage: python program.py <file1> <file2>")
        sys.exit(1)

    file1_path = sys.argv[1]
    file2_path = sys.argv[2]

    common_count = find_common_tokens(file1_path, file2_path)
    print(common_count)


if __name__ == "__main__":
    main()
