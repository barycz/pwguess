"""One-time download of the public data that real cracking setups use.

This script is the ONLY part of the project that touches the network, and it
never sees a password. It downloads plain-text wordlists and hashcat rule files
into ./data and ./rules. Run it once:

    python fetch_data.py
"""
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

FILES = [
    # (destination, url)
    ("data/passwords.txt",
     "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/"
     "Common-Credentials/xato-net-10-million-passwords-1000000.txt"),
    ("data/en_words.txt",
     "https://raw.githubusercontent.com/hermitdave/FrequencyWords/master/content/2018/en/en_50k.txt"),
    ("rules/best66.rule",
     "https://raw.githubusercontent.com/hashcat/hashcat/master/rules/best66.rule"),
    ("rules/leetspeak.rule",
     "https://raw.githubusercontent.com/hashcat/hashcat/master/rules/leetspeak.rule"),
    ("rules/rockyou-30000.rule",
     "https://raw.githubusercontent.com/hashcat/hashcat/master/rules/rockyou-30000.rule"),
    ("rules/dive.rule",
     "https://raw.githubusercontent.com/hashcat/hashcat/master/rules/dive.rule"),
]


def main():
    for rel, url in FILES:
        dest = os.path.join(HERE, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.exists(dest) and "--force" not in sys.argv:
            print(f"exists   {rel}")
            continue
        print(f"download {rel}  <-  {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "pwguess-fetch"})
        with urllib.request.urlopen(req, timeout=120) as r, open(dest + ".part", "wb") as f:
            while chunk := r.read(1 << 16):
                f.write(chunk)
        os.replace(dest + ".part", dest)
        print(f"         {os.path.getsize(dest):,} bytes")
    # Invalidate trained-model cache, if any.
    cache = os.path.join(HERE, "data", "model_cache.pkl")
    if os.path.exists(cache):
        os.remove(cache)
    print("done.")


if __name__ == "__main__":
    main()
