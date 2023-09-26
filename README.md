# sha3bit

| | |
| --- | --- |
| CI/CD | [![CI - Test](https://github.com/sebastien-riou/sha3bit/actions/workflows/test.yml/badge.svg)](https://github.com/sebastien-riou/sha3bit/actions/workflows/test.yml) [![CD - Build](https://github.com/sebastien-riou/sha3bit/actions/workflows/build.yml/badge.svg)](https://github.com/sebastien-riou/sha3bit/actions/workflows/build.yml) [![Documentation Status](https://readthedocs.org/projects/sha3bit/badge/?version=latest)](https://sha3bit.readthedocs.io/en/latest/?badge=latest)|
| Package | [![PyPI - Version](https://img.shields.io/pypi/v/sha3bit.svg?logo=pypi&label=PyPI&logoColor=gold)](https://pypi.org/project/sha3bit/) [![PyPI - Python Version](https://img.shields.io/pypi/pyversions/sha3bit.svg?logo=python&label=Python&logoColor=gold)](https://pypi.org/project/sha3bit/) |
| Meta | [![Hatch project](https://img.shields.io/badge/%F0%9F%A5%9A-Hatch-4051b5.svg)](https://github.com/pypa/hatch)  [![linting - Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/charliermarsh/ruff/main/assets/badge/v0.json)](https://github.com/charliermarsh/ruff) [![code style - Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![types - Mypy](https://img.shields.io/badge/types-Mypy-blue.svg)](https://github.com/python/mypy) [![License - apache-2.0](https://img.shields.io/badge/license-apache--2.0-blue)](https://spdx.org/licenses/) |


Pure python implementation of SHA3 with features which are often lacking:
- Bit granularity for message input length
- Import/export API to "persist" the state in the middle of a hash computation
- Real `squeez` function in addition of hashlib's `digest`
- Builtin logging to see compression function IOs or even internal steps

[User documentation](https://sha3bit.rtfd.io) is hosted on readthedocs.

## Installation

    python3 -m pip install sha3bit

## Usage

### One liner 

    >>> from sha3bit import sha3_256
    >>> print(sha3_256("abc".encode()).hexdigest())
    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'

### Bit length capability

    >>> from sha3bit import sha3_256
    >>> print(sha3_256(b'\x00',bitlen=1).hexdigest())
    '1b2e61923578e35f3b4629e04a0ff3b73daa571ae01130d9c16ef7da7a4cfdc2'

### Import/export

    >>> from sha3bit import sha3_256
    >>> h1 = sha3_256("a".encode())
    >>> state = h1.export_state()
    >>> h2 = sha3_256.import_state(state)
    >>> h2.update("bc".encode())
    >>> print(h2.hexdigest())
    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'

## Test with `pytest`

    pytest-3

## Test without `pytest`
Tests can run without creating/installing the package:

    python3 -m test.test


you can also run each test separately:

    python3 -m test.test_api
    python3 -m test.test_api_xof_absorb
    python3 -m test.test_cavp
    python3 -m test.test_cavp_xof
    python3 -m test.test_hardcoded
    python3 -m test.test_sha3_vs_hashlib
    python3 -m test.test_shake_vs_hashlib

## Generate the doc

    cd docs
    pipenv shell
    make clean doctest html

## Update pipenv for the doc

    cd docs
    pipenv shell
    #use pip to update whatever ou want
    pip freeze > requirements.txt
    pipenv update
    
## Build the package
Build is done using `hatchling`. The script `build` allows to build for different version of python3:

    ./build python3.9


## Create a new version
Version is managed by `hatch-vcs`, you just need to create a tag in github. 

## Launch linters
They use the configuration from `pyproject.toml`

    ./lint
