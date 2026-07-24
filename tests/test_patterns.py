from pki.patterns import expand_pattern, expand_patterns


def ids(pattern):
    return [r.id for r in expand_pattern(pattern)]


def test_literal():
    assert ids("7VH") == ["7VH"]


def test_wildcard():
    robots = ids("7V*")

    assert len(robots) == 36

    assert "7V0" in robots
    assert "7VA" in robots
    assert "7VZ" in robots


def test_numeric_range():

    assert ids("R{001-003}") == [
        "R001",
        "R002",
        "R003",
    ]


def test_character_class():

    assert ids("LAB[1-3]") == [
        "LAB1",
        "LAB2",
        "LAB3",
    ]


def test_alternatives():

    assert ids("T{A,B,C}") == [
        "TA",
        "TB",
        "TC",
    ]


def test_duplicate_removal():

    robots = list(expand_patterns([
        "7V*",
        "7VH",
        "7VA",
        "7V0",
    ]))

    assert len(robots) == 36