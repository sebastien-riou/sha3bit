****************
CLI examples
****************

Display help
============

..  code-block:: shell
    
    $ python3 -m sha3bit.cli --help
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


SHA3-256 of hex string
======================
This compute the SHA3-256 of the message "abc" (which is '61 62 63' in ASCII)

..  code-block:: shell
    
    $ python3 -m sha3bit.cli --sha3-256 616263
    3A 98 5D A7 4F E2 25 B2 04 5C 17 2D 6B D3 90 BD 85 5F 08 6E 3E 9D 52 5B 46 BF E2 45 11 43 15 32


You can also separate the bytes:
..  code-block:: shell
    
    $ python3 -m sha3bit.cli --sha3-256 '61 62 63'
    3A 98 5D A7 4F E2 25 B2 04 5C 17 2D 6B D3 90 BD 85 5F 08 6E 3E 9D 52 5B 46 BF E2 45 11 43 15 32


Commas are supported:
..  code-block:: shell
    
    $ python3 -m sha3bit.cli --sha3-256 '0x61, 0x62, 0x63'
    3A 98 5D A7 4F E2 25 B2 04 5C 17 2D 6B D3 90 BD 85 5F 08 6E 3E 9D 52 5B 46 BF E2 45 11 43 15 32


Bit length capability
=====================

SHA3-256 of single bit message '0':
..  code-block:: shell
    
    $ python3 -m sha3bit.cli --sha3-256 '00' --bit-length=1
    1B 2E 61 92 35 78 E3 5F 3B 46 29 E0 4A 0F F3 B7 3D AA 57 1A E0 11 30 D9 C1 6E F7 DA 7A 4C FD C2


SHA3-256 of single bit message '1':
..  code-block:: shell
    
    $ python3 -m sha3bit.cli --sha3-256 '01' --bit-length=1
    83 F6 62 16 D2 CC 76 9E 15 3B AF CE 01 81 B6 1A 47 1B 4C 6A 21 3F C6 F5 9A 42 98 5F 97 6F 33 FE    


SHA3-256 of two bits message '10':
..  code-block:: shell
    
    $ python3 -m sha3bit.cli --sha3-256 '01' --bit-length=2
    35 89 C9 5B A0 B3 CF C5 DE 7C 86 88 41 3F DA 5A 2D 5A 55 BB B1 06 90 04 69 F6 C5 E4 17 0E C9 59


SHA3-256 of two bits message '01':
..  code-block:: shell
    
    $ python3 -m sha3bit.cli --sha3-256 '02' --bit-length=2
    48 59 15 F6 3F CF 56 7B 8C 3D FA FE F3 68 D1 90 AE DB 8A 60 F5 52 2B E7 7F 2D AA B8 3B 75 7C 35


Dumping intermediate values
============================
This is useful to people working on their own implemention of SHA3.
The verbosity is controlled by the logging level. 

- Use 'INFO' to dump block level information
- Use 'DEBUG' to dump all intermediate values

..  code-block:: shell
    
    $ python3 -m sha3bit.cli --sha3-256 616263 --log-level=INFO
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