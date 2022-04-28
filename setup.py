#!/usr/bin/env python
"""lattice-cryptography distutils configuration."""
import os
import codecs

from setuptools import setup, find_packages


with open("README.md", encoding="utf-8") as readme_file:
    readme = readme_file.read()


def _read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), "r") as fp:
        return fp.read()


def get_version(rel_path):
    """Get the version from the __version__ file in the lattice_cryptography dir."""
    for line in _read(rel_path).splitlines():
        if line.startswith("__version__"):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError("Unable to find version string.")


setup(
    name="lattice_cryptography",
    version=get_version(os.path.join("lattice_cryptography", "__init__.py")),
    description=(
        "Implementation of lattice cryptography primitives"
    ),
    long_description=readme,
    long_description_content_type="text/markdown",
    author="Geometry Labs",
    author_email="info@geometrylabs.io",
    url="https://github.com/geometry-labs/lattice-cryptography",
    packages=find_packages(exclude=["tests*", "docs*", ".github*"]),
    package_dir={"lattice_cryptography": "lattice_cryptography"},
    include_package_data=True,
    install_requires=['lattice_algebra==0.1.1'],
    python_requires=">=3.6",
    license="MIT",
    zip_safe=False,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Financial and Insurance Industry",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python",
        "Topic :: Software Development",
        "Topic :: Scientific/Engineering :: Mathematics",
        "Topic :: Security :: Cryptography",
        "Typing :: Typed",
    ],
    keywords=[
        "lattice",
        "cryptography",
        "crypto",
        "signatures"
    ],
)