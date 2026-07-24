"""
naming.py

Naming helpers for robots.
"""

from pathlib import Path

from pki.models import RobotIdentity, ProjectPaths
from pki.config import ServerConfig


def alias(
    robot: RobotIdentity,
    server: ServerConfig,
) -> str:
    return f"{server.prefix}{robot.id.lower()}"


def hostname(
    robot: RobotIdentity,
    server: ServerConfig,
) -> str:
    return f"{alias(robot, server)}{server.suffix}"


def url(
    robot: RobotIdentity,
    server: ServerConfig,
) -> str:
    return f"https://{hostname(robot, server)}:{server.port}"


def key_path(
    robot: RobotIdentity,
    server: ServerConfig,
    paths: ProjectPaths,
) -> Path:
    return paths.robots / f"{alias(robot, server)}.key"


def certificate_path(
    robot: RobotIdentity,
    server: ServerConfig,
    paths: ProjectPaths,
) -> Path:
    return paths.robots / f"{alias(robot, server)}.crt"


def p12_alias(
    robot: RobotIdentity,
    server: ServerConfig,
) -> str:
    return alias(robot, server)