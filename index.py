"""Password strength tester and generator.

Educational portfolio project. Estimates guess resistance from length,
character classes, and simple pattern penalties. Does not replace a
breach check (Have I Been Pwned) or a real estimator such as zxcvbn.
"""

from __future__ import annotations

import math
import re
import secrets
import string
from dataclasses import dataclass

# A tiny built-in denylist. A real product should check a breach corpus
# (for example the Have I Been Pwned range API), not this list.

COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678",
    "123456789", "qwerty", "qwerty123", "letmein", "admin", "welcome",
    "iloveyou", "monkey", "dragon", "abc123", "111111", "passw0rd",
    "p@ssw0rd", "p@ssword", "changeme", "trustno1",
}

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")

RATING_ORDER = ("Very weak", "Weak", "Fair", "Strong", "Very strong")

MINIMUM_ACCEPTED = "Strong"


@dataclass(frozen=True)
class StrengthReport:
    password: str
    score: int
    rating: str
    entrophy_bits: float
    length: int
    classes: tuple[str, ...]
    problems: tuple[str, ...]
    suggestions: tuple[str, ...]

    @property
    def accepted(self) -> bool:
        return RATING_ORDER.index(self.rating) >= RATING_ORDER.index(MINIMUM_ACCEPTED)



def character_classes(password: str) -> tuple[str, ...]:
    """Return the names of character classes actually present."""
    found: list[str] = []
    if any(c.islower() for c in password):
        found.append("lowercase")
    if any(c.isupper() for c in password):
        found.append("uppercase")
    if any(c.isdigit() for c in password):
        found.append("digit")
    if any(not c.isalnum() for c in password):
        found.append("symbol")
    return tuple(found)

def alphabet_size(classes: tuple[str, ...]) -> int:
    """Size of the pool an attacker must search if they know the classes used."""
    size = 0
    if "lowercase" in classes:
        size += 26
    if "uppercase" in classes:
        size += 26
    if "digit" in classes:
        size += 10
    if "symbol" in classes:
        size += 33
    return size

def entropy_bits(password: str, classes: tuple[str, ...]) -> float:
    """Naive Shannon-style estimate: length * log2(alphabet).

    This assumes each character was chosen independently and uniformly.
    Humans do not do that, so this number is an upper bound, not a fact.
    """

    pool = alphabet_size(classes)
    if pool <= 1 or not password:
        return 0.0
    return len(password) * math.log2(pool)


def has_repeated(password: str, run: int = 3) -> bool:
    return re.search(rf"(.)\1{{{run -1}, }}", password) is not None


def has_sequence(password: str, length: int = 4) -> bool:
    """Detect ascending or descending runs like abcd or 9876."""
    lowered = password.lower()
    for i in range(len(lowered) - length + 1):
        chunk = lowered[i:i + length]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(length - 1)):
            return True
        if all(ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(length - 1)):
            return True
    return False

def has_keyboard_walk(password: str, length: int = 4) -> bool:
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        reversed_row = row[::-1]
        for i in range(len(lowered) - length + 1):
            chunk = lowered[i:i + length]
            if chunk in row or chunk in reversed_row:
                return True
    return False


def analyze(password: str) -> StrengthReport:
    """Score a password and collect human-readable feedback."""
    problems: list[str] = []
    suggestions: list[str] = []
    classes = character_classes(password)
    bits = entropy_bits(password, classes)
    score = 0

    # Length is the dominant term. Caps keep one trait from maxing the score alone.