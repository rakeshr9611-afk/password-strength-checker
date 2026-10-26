#!/usr/bin/env python3
"""Password strength checker.

Scores a password on length, character variety, estimated entropy and
common weak patterns, and optionally checks whether it appears in known
data breaches using the Have I Been Pwned "range" API (k-anonymity: only
the first 5 characters of the SHA-1 hash ever leave your machine).
"""

import argparse
import getpass
import hashlib
import json
import math
import re
import string
import sys
import urllib.error
import urllib.request

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "football", "monkey", "letmein", "111111", "1234567",
    "dragon", "baseball", "iloveyou", "trustno1", "sunshine", "master",
    "welcome", "shadow", "ashley", "superman", "passw0rd", "admin",
    "login", "princess", "qwertyuiop", "solo", "starwars", "hello",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                          "7": "t", "@": "a", "$": "s", "!": "i"})


def charset_size(password):
    """Return the size of the character pool the password draws from."""
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += len(string.punctuation)
    if any(c not in string.printable for c in password):
        size += 100  # rough allowance for unicode characters
    return size


def entropy_bits(password):
    """Estimate brute-force entropy in bits (length * log2(pool size))."""
    pool = charset_size(password)
    if not password or pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def has_sequence(password, run=4):
    """Detect runs like 'abcd', '4321' or keyboard rows like 'qwer'."""
    lower = password.lower()
    sources = [string.ascii_lowercase, string.digits] + KEYBOARD_ROWS
    for src in sources:
        for seq in (src, src[::-1]):
            for i in range(len(seq) - run + 1):
                if seq[i:i + run] in lower:
                    return True
    return False


def find_weaknesses(password):
    """Return a list of human-readable weaknesses found in the password."""
    issues = []
    lower = password.lower()
    if len(password) < 8:
        issues.append("Too short (fewer than 8 characters)")
    elif len(password) < 12:
        issues.append("Short (12+ characters recommended)")
    if lower in COMMON_PASSWORDS or lower.translate(LEET_MAP) in COMMON_PASSWORDS:
        issues.append("Is a very common password (or a leetspeak variant)")
    if not any(c.islower() for c in password):
        issues.append("No lowercase letters")
    if not any(c.isupper() for c in password):
        issues.append("No uppercase letters")
    if not any(c.isdigit() for c in password):
        issues.append("No digits")
    if not any(c in string.punctuation for c in password):
        issues.append("No symbols")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains a character repeated 3+ times")
    if has_sequence(password):
        issues.append("Contains a sequential or keyboard pattern")
    if re.search(r"(19|20)\d{2}", password):
        issues.append("Contains what looks like a year")
    return issues


def score_password(password):
    """Return (score 0-4, label, entropy, weaknesses)."""
    bits = entropy_bits(password)
    weaknesses = find_weaknesses(password)

    if bits < 28:
        score = 0
    elif bits < 36:
        score = 1
    elif bits < 60:
        score = 2
    elif bits < 80:
        score = 3
    else:
        score = 4

    # Patterns make a password far easier to guess than raw entropy suggests.
    penalties = sum(1 for w in weaknesses if w.startswith(("Is a very common",
                                                            "Contains")))
    if any(w.startswith("Is a very common") for w in weaknesses):
        score = 0
    else:
        score = max(0, score - penalties)

    label = ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score]
    return score, label, bits, weaknesses


def crack_time(bits, guesses_per_second=1e10):
    """Human-readable average time to brute-force at the given guess rate."""
    seconds = (2 ** bits) / 2 / guesses_per_second
    for unit, size in (("years", 31_536_000), ("days", 86_400),
                       ("hours", 3_600), ("minutes", 60)):
        if seconds >= size:
            value = seconds / size
            if unit == "years" and value > 1e6:
                return "millions of years+"
            return f"~{value:,.1f} {unit}"
    return "less than a minute"


def pwned_count(password, timeout=10):
    """Return how many times the password appears in HIBP breach data.

    Only the first 5 hex chars of the SHA-1 hash are sent (k-anonymity).
    Returns None if the API could not be reached.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    req = urllib.request.Request(
        HIBP_RANGE_URL.format(prefix),
        headers={"User-Agent": "password-strength-checker", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError):
        return None
    for line in body.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip() == suffix:
            return int(count)
    return 0


def analyze(password, check_breach=True):
    score, label, bits, weaknesses = score_password(password)
    result = {
        "length": len(password),
        "score": score,
        "rating": label,
        "entropy_bits": round(bits, 1),
        "estimated_crack_time": crack_time(bits),
        "weaknesses": weaknesses,
    }
    if check_breach:
        result["breach_count"] = pwned_count(password)
    return result


def print_report(result):
    bar = "#" * (result["score"] + 1) + "-" * (4 - result["score"])
    print(f"\nRating:       {result['rating']}  [{bar}]")
    print(f"Length:       {result['length']}")
    print(f"Entropy:      {result['entropy_bits']} bits")
    print(f"Crack time:   {result['estimated_crack_time']} (offline, 10B guesses/s)")
    if "breach_count" in result:
        count = result["breach_count"]
        if count is None:
            print("Breaches:     could not reach Have I Been Pwned")
        elif count:
            print(f"Breaches:     FOUND in {count:,} breaches. Do not use this password!")
        else:
            print("Breaches:     not found in known breaches")
    if result["weaknesses"]:
        print("Weaknesses:")
        for w in result["weaknesses"]:
            print(f"  - {w}")
    print()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check password strength and breach exposure.")
    parser.add_argument("--offline", action="store_true",
                        help="skip the Have I Been Pwned breach check")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--stdin", action="store_true",
                        help="read passwords from stdin, one per line")
    args = parser.parse_args(argv)

    if args.stdin:
        passwords = [line.rstrip("\n") for line in sys.stdin if line.strip()]
    else:
        passwords = [getpass.getpass("Password (input hidden): ")]

    results = [analyze(p, check_breach=not args.offline) for p in passwords]
    if args.json:
        print(json.dumps(results if args.stdin else results[0], indent=2))
    else:
        for r in results:
            print_report(r)
    return 0 if all(r["score"] >= 3 for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
