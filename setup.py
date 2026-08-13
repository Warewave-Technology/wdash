"""
WDash setup script
"""

import re

from setuptools import setup, find_packages


def _version():
    """Read from the package rather than repeated here.

    Two copies of a version number are two claims, and they had already
    parted company.
    """
    source = open("src/wdash/__init__.py", encoding="utf-8").read()
    return re.search(r'__version__ = "([^"]+)"', source).group(1)

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="wdash",
    version=_version(),
    author="Warewave",
    description="A minimal Kibana alternative with RBAC and OIDC support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: System :: Monitoring",
    ],
    # 3.11 is what the image ships and the lowest version CI runs. The
    # previous claim was ">=3.8" with classifiers down to 3.8, and it was not
    # true for either half: `psycopg==3.3.4` needs 3.10, `cryptography` and
    # `requests` need 3.9, so `pip install wdash` on 3.8 could never have
    # resolved. Claiming a version nothing tests is a promise made to
    # somebody else's afternoon.
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "wdash=wdash.app:main",
        ],
    },
)