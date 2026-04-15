#!/usr/bin/env python3
"""
Password Hash Cracker
=====================
Dictionary-based hash cracker with mutation rules.
Supports MD5, SHA1, SHA256, SHA512, NTLM, and bcrypt.
For authorized use only - only crack hashes you own.
"""

import hashlib
import itertools
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass
class CrackResult:
    hash_value: str
    algorithm: str
    plaintext: str | None
    attempts: int
    duration: float
    found: bool


# Length-based auto-detection
HASH_PATTERNS = {
    "md5": (32, re.compile(r"^[a-fA-F0-9]{32}$")),
    "sha1": (40, re.compile(r"^[a-fA-F0-9]{40}$")),
    "sha256": (64, re.compile(r"^[a-fA-F0-9]{64}$")),
    "sha512": (128, re.compile(r"^[a-fA-F0-9]{128}$")),
    "ntlm": (32, re.compile(r"^[a-fA-F0-9]{32}$")),  # Same length as MD5
    "bcrypt": (60, re.compile(r"^\$2[aby]?\$\d{1,2}\$.{53}$")),
}

# Leet speak substitutions
LEET_MAP = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
    "l": ["1"],
    "g": ["9"],
}

# Common suffixes to try
COMMON_SUFFIXES = ["", "1", "12", "123", "1234", "!", "!!", "?", ".", "01", "69", "007", "2024", "2025", "2026"]
COMMON_PREFIXES = ["", "!", "@", "#", "1", "the"]


def detect_hash_type(hash_value: str) -> str:
    """Auto-detect hash algorithm from hash format."""
    # Check bcrypt first (distinctive format)
    if hash_value.startswith("$2"):
        return "bcrypt"

    hash_len = len(hash_value)
    if hash_len == 32:
        return "md5"  # Could also be NTLM, but MD5 is more common
    elif hash_len == 40:
        return "sha1"
    elif hash_len == 64:
        return "sha256"
    elif hash_len == 128:
        return "sha512"
    return "md5"  # Default fallback


def compute_hash(plaintext: str, algorithm: str) -> str:
    """Compute hash for a given plaintext and algorithm."""
    data = plaintext.encode("utf-8")

    if algorithm == "md5":
        return hashlib.md5(data).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(data).hexdigest()
    elif algorithm == "ntlm":
        return hashlib.new("md4", plaintext.encode("utf-16le")).hexdigest()
    elif algorithm == "bcrypt":
        try:
            import bcrypt as bcrypt_lib
            return bcrypt_lib.hashpw(data, hash_value.encode()).decode()
        except ImportError:
            print("  [!] Install bcrypt: pip install bcrypt")
            sys.exit(1)
    return ""


def check_bcrypt(plaintext: str, hash_value: str) -> bool:
    """Check if plaintext matches a bcrypt hash."""
    try:
        import bcrypt as bcrypt_lib
        return bcrypt_lib.checkpw(plaintext.encode("utf-8"), hash_value.encode("utf-8"))
    except ImportError:
        print("  [!] Install bcrypt: pip install bcrypt")
        sys.exit(1)
    except Exception:
        return False


def apply_mutations(word: str) -> list[str]:
    """Apply mutation rules to generate word variants."""
    variants = set()
    variants.add(word)

    # Case mutations
    variants.add(word.lower())
    variants.add(word.upper())
    variants.add(word.capitalize())
    variants.add(word.swapcase())
    variants.add(word.title())

    # Reverse
    variants.add(word[::-1])

    # Add suffixes / prefixes
    for suffix in COMMON_SUFFIXES:
        variants.add(word + suffix)
        variants.add(word.capitalize() + suffix)
    for prefix in COMMON_PREFIXES:
        variants.add(prefix + word)

    # Leet speak (single pass)
    leet = word.lower()
    for char, replacements in LEET_MAP.items():
        for replacement in replacements:
            leet_variant = leet.replace(char, replacement)
            if leet_variant != leet:
                variants.add(leet_variant)
                for suffix in ["", "1", "!", "123"]:
                    variants.add(leet_variant + suffix)

    # Double the word
    variants.add(word + word)

    return list(variants)


def crack_hash_worker(candidates: list[str], target_hash: str, algorithm: str) -> str | None:
    """Worker function to check a batch of candidates."""
    target_lower = target_hash.lower()
    for candidate in candidates:
        if algorithm == "bcrypt":
            if check_bcrypt(candidate, target_hash):
                return candidate
        else:
            if compute_hash(candidate, algorithm).lower() == target_lower:
                return candidate
    return None


def run_hash_cracker(args):
    """Main hash cracker entry point."""
    hash_value = args.hash_value.strip()
    wordlist_path = args.wordlist
    use_rules = args.rules
    algorithm = args.mode

    if algorithm == "auto":
        algorithm = detect_hash_type(hash_value)

    print(f"  [*] Hash: {hash_value}")
    print(f"  [*] Algorithm: {algorithm.upper()}")
    print(f"  [*] Wordlist: {wordlist_path}")
    print(f"  [*] Mutation rules: {'enabled' if use_rules else 'disabled'}")

    if not os.path.isfile(wordlist_path):
        print(f"  [✗] Wordlist not found: {wordlist_path}")
        return

    # Count lines for progress
    print("  [*] Loading wordlist...")
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]
    total_words = len(words)
    print(f"  [*] Loaded {total_words:,} words")

    if use_rules:
        estimated = total_words * 30  # Rough estimate with mutations
        print(f"  [*] Estimated candidates with mutations: ~{estimated:,}")

    print()
    print("  [*] Cracking started...")
    print()

    start_time = time.time()
    attempts = 0
    found_plaintext = None
    batch_size = 1000

    try:
        for i, word in enumerate(words):
            if found_plaintext:
                break

            # Generate candidates
            if use_rules:
                candidates = apply_mutations(word)
            else:
                candidates = [word]

            # Check candidates
            for candidate in candidates:
                attempts += 1
                if algorithm == "bcrypt":
                    if check_bcrypt(candidate, hash_value):
                        found_plaintext = candidate
                        break
                else:
                    if compute_hash(candidate, algorithm).lower() == hash_value.lower():
                        found_plaintext = candidate
                        break

            # Progress update
            if (i + 1) % 500 == 0 or i == total_words - 1:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                pct = (i + 1) / total_words * 100
                bar_len = 35
                filled = int(bar_len * (i + 1) / total_words)
                bar = "█" * filled + "░" * (bar_len - filled)
                sys.stdout.write(
                    f"\r  [{bar}] {pct:.1f}% | {attempts:,} hashes | {rate:,.0f} H/s"
                )
                sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted by user")

    duration = time.time() - start_time
    print("\n")

    # Results
    print("  ┌───────────────────────────────────────────────────┐")
    if found_plaintext:
        print("  │  ✓ PASSWORD FOUND!                                │")
        print("  ├───────────────────────────────────────────────────┤")
        print(f"  │  Hash:      {hash_value[:45]}")
        print(f"  │  Plaintext: {found_plaintext}")
        print(f"  │  Algorithm: {algorithm.upper()}")
        print(f"  │  Attempts:  {attempts:,}")
        print(f"  │  Time:      {duration:.2f}s")
        rate = attempts / duration if duration > 0 else 0
        print(f"  │  Rate:      {rate:,.0f} hashes/sec")
    else:
        print("  │  ✗ PASSWORD NOT FOUND                             │")
        print("  ├───────────────────────────────────────────────────┤")
        print(f"  │  Exhausted {attempts:,} candidates in {duration:.2f}s")
        print(f"  │  Try a larger wordlist or enable --rules")
    print("  └───────────────────────────────────────────────────┘")
