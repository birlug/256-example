import sys
from pathlib import Path

from .compress import compress_input
from .decompress import decompress_output


def main(argv: list[str]) -> int:
    mode, src, dst = argv[1], argv[2], argv[3]
    data = Path(src).read_bytes()
    if mode == "--compress":
        Path(dst).write_bytes(compress_input(data))
        return 0
    if mode == "--decompress":
        Path(dst).write_bytes(decompress_output(data))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
