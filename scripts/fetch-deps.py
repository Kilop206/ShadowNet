"""Populate a local source cache; CMake verifies each archive independently.

Use --direct only when the environment's configured proxy is unavailable.
No certificates are bypassed and no dependency source is modified.
"""
import argparse
import concurrent.futures
import hashlib
from pathlib import Path
import urllib.request

PACKAGES = {
    "boost-1.90.0-cmake.tar.gz": "https://github.com/boostorg/boost/releases/download/boost-1.90.0/boost-1.90.0-cmake.tar.gz",
    "yaml-cpp-0.9.0.tar.gz": "https://codeload.github.com/jbeder/yaml-cpp/tar.gz/refs/tags/yaml-cpp-0.9.0",
    "Catch2-3.8.1.tar.gz": "https://codeload.github.com/catchorg/Catch2/tar.gz/refs/tags/v3.8.1",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--direct", action="store_true")
    args = parser.parse_args()
    cache = Path(__file__).resolve().parents[1] / ".deps"
    cache.mkdir(exist_ok=True)

    def fetch(item):
        name, url = item
        path = cache / name
        if not path.exists():
            opener = urllib.request.build_opener(*([urllib.request.ProxyHandler({})] if args.direct else []))
            temporary = path.with_suffix(".part")
            with opener.open(url, timeout=60) as source, temporary.open("wb") as target:
                while chunk := source.read(1024 * 1024):
                    target.write(chunk)
            temporary.replace(path)
        return f"{name}: {hashlib.sha256(path.read_bytes()).hexdigest()}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        for result in executor.map(fetch, PACKAGES.items()):
            print(result, flush=True)


if __name__ == "__main__":
    main()
