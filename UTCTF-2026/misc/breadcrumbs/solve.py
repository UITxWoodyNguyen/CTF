#!/usr/bin/env python3

"""
Sample output:
[+] Step 0 - Start URL: https://gist.github.com/garvk07/3f9c505068c011e0fd6abd9ddf56aecb
[+] Step 1 - start.txt: Base64 -> https://gist.github.com/garvk07/ba406460f2e932b5496ca25977be25be
[+] Step 2 - poem.txt: embedded URL -> https://gist.github.com/garvk07/963e70be662ea81e96e4e63553038d1a
[+] Step 3 - analysis.py: hex -> https://gist.github.com/garvk07/5d5ef859f530c3d593a4a3c7580d2f29
[+] Step 4 - final.txt: ROT13 token -> hgsynt{s0yy0j1at_gu3_pe4jy_ge41y}
[+] FLAG: utflag{f0ll0w1ng_th3_cr4wl_tr41l}
"""

import base64
import codecs
import json
import re
import urllib.request
from urllib.parse import urlparse


START_URL = "https://gist.github.com/garvk07/3f9c505068c011e0fd6abd9ddf56aecb"


def extract_gist_id(url: str) -> str:
    path_parts = [part for part in urlparse(url).path.split("/") if part]
    if not path_parts:
        raise ValueError(f"Cannot extract gist id from URL: {url}")
    return path_parts[-1]


def fetch_gist(gist_url: str) -> dict:
    gist_id = extract_gist_id(gist_url)
    api_url = f"https://api.github.com/gists/{gist_id}"
    request = urllib.request.Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ctf-breadcrumb-solver",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def first_file_content(gist_obj: dict) -> tuple[str, str]:
    files = gist_obj.get("files", {})
    if not files:
        raise ValueError("No files found in gist")
    filename, metadata = next(iter(files.items()))
    content = metadata.get("content", "")
    return filename, content


def extract_base64_url(text: str) -> str:
    compact = "".join(line.strip() for line in text.splitlines())
    candidates = re.findall(r"[A-Za-z0-9+/=]{40,}", compact)
    if not candidates:
        raise ValueError("No Base64 candidate found")
    decoded = base64.b64decode(candidates[0]).decode()
    if not decoded.startswith("http"):
        raise ValueError("Decoded Base64 does not look like URL")
    return decoded


def extract_url(text: str) -> str:
    match = re.search(r"https://gist\.github\.com/[\w-]+/[0-9a-f]{32}", text)
    if not match:
        raise ValueError("No gist URL found")
    return match.group(0)


def extract_hex_url(text: str) -> str:
    compact = "".join(line.strip() for line in text.splitlines())
    candidates = re.findall(r"[0-9a-fA-F]{40,}", compact)
    if not candidates:
        raise ValueError("No hex candidate found")
    decoded = bytes.fromhex(candidates[0]).decode()
    if not decoded.startswith("http"):
        raise ValueError("Decoded hex does not look like URL")
    return decoded


def extract_rot13_flag(text: str) -> tuple[str, str]:
    match = re.search(r"[a-z]{4,}\{[^}\n]+\}", text)
    if not match:
        raise ValueError("No flag-like token found")
    encoded_flag = match.group(0)
    decoded_flag = codecs.decode(encoded_flag, "rot_13")
    return encoded_flag, decoded_flag


def main() -> None:
    print("[+] Step 0 - Start URL:", START_URL)

    gist1 = fetch_gist(START_URL)
    file1, content1 = first_file_content(gist1)
    url2 = extract_base64_url(content1)
    print(f"[+] Step 1 - {file1}: Base64 -> {url2}")

    gist2 = fetch_gist(url2)
    file2, content2 = first_file_content(gist2)
    url3 = extract_url(content2)
    print(f"[+] Step 2 - {file2}: embedded URL -> {url3}")

    gist3 = fetch_gist(url3)
    file3, content3 = first_file_content(gist3)
    url4 = extract_hex_url(content3)
    print(f"[+] Step 3 - {file3}: hex -> {url4}")

    gist4 = fetch_gist(url4)
    file4, content4 = first_file_content(gist4)
    encoded_flag, flag = extract_rot13_flag(content4)
    print(f"[+] Step 4 - {file4}: ROT13 token -> {encoded_flag}")
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()