from itertools import product
from pki.models import RobotIdentity
import re

# Alphabet used by *
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class PatternError(Exception):
    pass


def expand_pattern(pattern: str):
    """
    Expands one robot pattern into RobotIdentity objects.

    Supported syntax:

        *
        [ABC]
        [A-Z]
        [0-9]
        [A-Z0-9]
        {001-120}
        {A,B,C}

    Examples:

        7V*
        LAB[1-5]
        R{001-010}
        T{A,B}[123]
    """

    pattern = pattern.strip().upper()

    tokens = tokenize(pattern)

    for parts in product(*tokens):
        yield RobotIdentity("".join(parts))


def expand_patterns(patterns):
    """
    Expands multiple patterns, removing duplicates.

    Parameters
    ----------
    patterns : iterable[str]

    Returns
    -------
    generator[RobotIdentity]
    """

    seen = set()

    for pattern in patterns:
        for robot in expand_pattern(pattern):

            if robot.id in seen:
                continue

            seen.add(robot.id)

            yield robot


def tokenize(pattern):

    tokens = []

    i = 0

    while i < len(pattern):

        c = pattern[i]

        #
        # Wildcard
        #
        if c == "*":

            tokens.append(list(ALPHABET))
            i += 1
            continue

        #
        # Character class [...]
        #
        if c == "[":

            try:
                end = pattern.index("]", i)
            except ValueError:
                raise PatternError(f"Missing ] in pattern '{pattern}'")

            content = pattern[i + 1:end]

            chars = expand_character_class(content)

            tokens.append(chars)

            i = end + 1
            continue

        #
        # Curly braces {...}
        #
        if c == "{":

            try:
                end = pattern.index("}", i)
            except ValueError:
                raise PatternError(f"Missing }} in pattern '{pattern}'")

            content = pattern[i + 1:end]

            tokens.append(expand_braces(content))

            i = end + 1
            continue

        #
        # Literal character
        #
        tokens.append([c])

        i += 1

    return tokens


def expand_character_class(content):

    out = []

    i = 0

    while i < len(content):

        #
        # Range
        #
        if (
            i + 2 < len(content)
            and content[i + 1] == "-"
        ):

            start = content[i]
            end = content[i + 2]

            if ord(start) > ord(end):
                raise PatternError(
                    f"Invalid range {start}-{end}"
                )

            for code in range(ord(start), ord(end) + 1):
                out.append(chr(code))

            i += 3

        else:

            out.append(content[i])
            i += 1

    return out


def expand_braces(content):

    #
    # Numeric range
    #

    m = re.fullmatch(r"(\d+)-(\d+)", content)

    if m:

        a = int(m.group(1))
        b = int(m.group(2))

        if a > b:
            raise PatternError(
                f"Invalid numeric range {content}"
            )

        width = len(m.group(1))

        return [
            f"{i:0{width}d}"
            for i in range(a, b + 1)
        ]

    #
    # Alternatives
    #

    return [
        item.strip().upper()
        for item in content.split(",")
        if item.strip()
    ]