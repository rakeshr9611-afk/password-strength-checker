# Password Strength Checker

A Python command-line tool that rates password strength and checks whether a password has appeared in known data breaches. It uses only the Python standard library.

## Features

- **Strength score (0–4)** based on estimated entropy (length × log2 of the character pool)
- **Pattern detection:** common passwords (including leetspeak versions such as `P@ssw0rd`), repeated characters, sequences (`abcd`, `4321`), keyboard runs (`qwer`), and years
- **Crack-time estimate** for an offline attack at 10 billion guesses per second
- **Breach check** using the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API with **k-anonymity**: only the first 5 characters of the password's SHA-1 hash are sent, so the password itself never leaves your machine
- Hidden input (`getpass`), JSON output, and batch mode from stdin

## Usage

```bash
python3 pwcheck.py                 # prompts for a password (input hidden)
python3 pwcheck.py --offline       # skip the breach lookup
python3 pwcheck.py --json          # machine-readable output
cat list.txt | python3 pwcheck.py --stdin --offline --json
```

Example output:

```
Rating:       Very weak  [#----]
Length:       8
Entropy:      37.6 bits
Crack time:   less than a minute (offline, 10B guesses/s)
Breaches:     FOUND in 9,545,824 breaches. Do not use this password!
Weaknesses:
  - Short (12+ characters recommended)
  - Is a very common password (or a leetspeak variant)
  - No uppercase letters
  - No digits
  - No symbols
```

The exit code is `0` when every password scores Strong (3) or higher, and `1` otherwise, so the tool can be used in scripts.

## How the breach check works

1. Compute `SHA1(password)`, e.g. `5BAA61E4C9B9...`
2. Send only the prefix `5BAA6` to `https://api.pwnedpasswords.com/range/5BAA6`
3. The API returns every leaked hash suffix that starts with that prefix
4. Look for the rest of the hash in that list on your own machine

The `Add-Padding` header is also sent, so the size of the response doesn't reveal anything either.

## Running tests

```bash
python3 -m unittest discover -s tests -v
```

## Skills demonstrated

Password entropy, attacker cost modeling, k-anonymity, cryptographic hashing, secure input handling, and unit testing with mocks.

## License

MIT
