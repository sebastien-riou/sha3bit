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

## CLI usage

### Get help

````
python3 -m sha3bit.cli --help
usage: cli.py [-h] [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [--bit-length BIT_LENGTH] (--sha3-224 | --sha3-256 | --sha3-384 | --sha3-512 | --shake-128 | --shake-256) [--digest-size DIGEST_SIZE]
            message

sha3bit.cli

positional arguments:
message               Message to hash

optional arguments:
-h, --help            show this help message and exit
--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
--bit-length BIT_LENGTH
                        Bit length of message
--sha3-224            Use SHA3-224 algorythm
--sha3-256            Use SHA3-256 algorythm
--sha3-384            Use SHA3-384 algorythm
--sha3-512            Use SHA3-512 algorythm
--shake-128           Use SHAKE-128 algorythm
--shake-256           Use SHAKE-256 algorythm
--digest-size DIGEST_SIZE
                        Output size in bytes
````

### SHA3-256 of hex string
This compute the SHA3-256 of the message "abc" (which is '61 62 63' in ASCII)

````
python3 -m sha3bit.cli --sha3-256 616263
3A 98 5D A7 4F E2 25 B2 04 5C 17 2D 6B D3 90 BD 85 5F 08 6E 3E 9D 52 5B 46 BF E2 45 11 43 15 32
````

You can also separate the bytes:
````
python3 -m sha3bit.cli --sha3-256 '61 62 63'
3A 98 5D A7 4F E2 25 B2 04 5C 17 2D 6B D3 90 BD 85 5F 08 6E 3E 9D 52 5B 46 BF E2 45 11 43 15 32
````

Commas are supported:
````
python3 -m sha3bit.cli --sha3-256 '0x61, 0x62, 0x63'
3A 98 5D A7 4F E2 25 B2 04 5C 17 2D 6B D3 90 BD 85 5F 08 6E 3E 9D 52 5B 46 BF E2 45 11 43 15 32
````

### Showing internal steps
You can control the verbosity of the output using the `--log-level` argument.
- `--log-level=INFO` will display inputs/outputs of the compression function.
- `--log-level=DEBUG` will display all internal steps of the compression function.

````
python3 -m sha3bit.cli --sha3-256 616263 --log-level=INFO
process block:
            0                         1                         2                         3                         4              
0   61 62 63 06 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
1   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 80   
2   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
3   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
4   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
f1600 input:
            0                         1                         2                         3                         4              
0   61 62 63 06 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
1   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 80   00 00 00 00 00 00 00 00   
2   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
3   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
4   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
f1600 output:
            0                         1                         2                         3                         4              
0   3A 98 5D A7 4F E2 25 B2   27 3E 60 D6 AA C8 97 20   42 F7 4E A5 81 05 13 BF   EF 21 46 A8 DC 39 12 63   C8 BE 38 B9 5C 3E C5 5F   
1   04 5C 17 2D 6B D3 90 BD   F7 B1 3F 62 61 C5 F2 31   BF F8 A9 CD CE FC 92 30   BD E1 5F 39 66 78 3F 4B   C1 3C BC AC DC 22 FC 02   
2   85 5F 08 6E 3E 9D 52 5B   9C DF 04 F2 F3 74 DF 8F   62 08 F0 4A 2A 8B 8B 1A   8A 7D C6 FF 1B F9 BE 30   C3 6C 4B 8C 92 94 80 66   
3   46 BF E2 45 11 43 15 32   AC C4 86 B1 8D 83 5E 9F   05 A7 0C D9 90 CC C4 60   C9 06 DD D6 3D 51 72 D2   7D 1A 16 AE 29 51 C2 D5   
4   D1 36 F6 22 FB 92 10 F8   A2 BA 11 BC 04 1C 0A A8   4E 1E 85 54 32 79 24 1F   85 B5 EC 0A 60 AF A3 25   41 10 E9 96 9E 9C D8 B5   
-----------------------------------------------------------------------------------------------------------------------------------
digest: 3A 98 5D A7 4F E2 25 B2 04 5C 17 2D 6B D3 90 BD 85 5F 08 6E 3E 9D 52 5B 46 BF E2 45 11 43 15 32
````

## Python3 usage
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
