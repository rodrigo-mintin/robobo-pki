from pki.models import RobotIdentity


def test_robot_id_is_uppercased():
    robot = RobotIdentity("7vh")

    assert robot.id == "7VH"


def test_alias():
    robot = RobotIdentity("A01")

    assert robot.alias == "robobo-a01"


def test_hostname():
    robot = RobotIdentity("7VH")

    assert robot.hostname == "robobo-7vh.local"


def test_certificate_filename():
    robot = RobotIdentity("7VH")

    assert robot.certificate_filename == "robobo-7vh.crt"


def test_key_filename():
    robot = RobotIdentity("7VH")

    assert robot.key_filename == "robobo-7vh.key"


def test_p12_alias():
    robot = RobotIdentity("7VH")

    assert robot.p12_alias == "robobo-7vh"