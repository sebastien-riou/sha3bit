****************
Python3 examples
****************

One liner
=========

.. testcode::

	from sha3bit import sha3_256
	print(sha3_256("abc".encode()).hexdigest())

.. testoutput::

    3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532


Bit length capability
=====================

One liner
----------

.. testcode::

    from sha3bit import sha3_256
    print(sha3_256(b'\x00',bitlen=1).hexdigest())
    
.. testoutput::

    1b2e61923578e35f3b4629e04a0ff3b73daa571ae01130d9c16ef7da7a4cfdc2


Update / digest
-----------------

.. testcode::

    from sha3bit import sha3_256
    h = sha3_256()
    h.update(b'\x00',bitlen=1)
    print(h.hexdigest())
    
.. testoutput::

    1b2e61923578e35f3b4629e04a0ff3b73daa571ae01130d9c16ef7da7a4cfdc2

Import / export
=====================

.. testcode::

    from sha3bit import sha3_256
    h1 = sha3_256("a".encode())
    state = h1.export_state()
    h2 = sha3_256.import_state(state)
    h2.update("bc".encode())
    print(h2.hexdigest())

.. testoutput::

    3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532


Dumping intermediate values
============================
This is useful to people working on their own implemention of SHA256.
The verbosity is controlled by the logging level. 

- Use 'INFO' to dump block level information
- Use 'DEBUG' to dump all intermediate values

.. testsetup:: ['dump']

    import logging    
    class PrintHandler(logging.StreamHandler):
        def emit(self, record):
            msg = self.format(record)
            print(msg)
            self.flush()
    print_handler = PrintHandler()
    logger = logging.getLogger()
    logger.setLevel(logging.INFO) 
    logger.addHandler(print_handler)
    

.. testcode:: ['dump']
    :skipif: True

    import logging  
    from sha3bit import sha3_256
    logging.basicConfig(format='%(message)s', level='INFO')
    print(sha3_256("abc".encode(), verbose=True).hexdigest())

.. testoutput:: ['dump']
    :skipif: True

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
    3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532



.. testcode:: ['dump']
    :skipif: True

    import logging
    from pysatl import Utils
    from sha3bit import sha3_256
    logging.basicConfig(format='%(message)s', level='INFO')
    message = Utils.ba('E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6 E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4 3E 41 98 3F 5D 4C 94 56 5F E4 46 3C')
    h1 = sha3_256(message[0:64], verbose=True)
    state = h1.export_state()
    h2 = sha3_256.import_state(state)
    h2.update(message[64:])
    print(h2.hexdigest())
    
.. testoutput:: ['dump']
    :skipif: True

    exporting current state:
    capacity = 512
    state:                 0                         1                         2                         3                         4              
    0   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    1   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    2   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    3   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    4   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    cache:  E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6 E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4 3E 41 98 3F 5D 4C 94 56
    bitlen = 512
    importing state:
    capacity = 512
    state:                 0                         1                         2                         3                         4              
    0   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    1   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    2   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    3   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    4   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    cache:  E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6 E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4 3E 41 98 3F 5D 4C 94 56
    bitlen = 512
    process block:
                0                         1                         2                         3                         4              
    0   E3 B0 C4 42 98 FC 1C 14   0A 82 75 05 8E 29 9F CC   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    1   9A FB F4 C8 99 6F B9 24   03 81 53 45 45 F5 5C F4   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 80   
    2   27 AE 41 E4 64 9B 93 4C   3E 41 98 3F 5D 4C 94 56   00 00 00 00 00 00 00 00   
    3   A4 95 99 1B 78 52 B8 55   5F E4 46 3C 06 00 00 00   00 00 00 00 00 00 00 00   
    4   5D F6 E0 E2 76 13 59 D3   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    f1600 input:
                0                         1                         2                         3                         4              
    0   E3 B0 C4 42 98 FC 1C 14   0A 82 75 05 8E 29 9F CC   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    1   9A FB F4 C8 99 6F B9 24   03 81 53 45 45 F5 5C F4   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 80   00 00 00 00 00 00 00 00   
    2   27 AE 41 E4 64 9B 93 4C   3E 41 98 3F 5D 4C 94 56   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    3   A4 95 99 1B 78 52 B8 55   5F E4 46 3C 06 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    4   5D F6 E0 E2 76 13 59 D3   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   
    f1600 output:
                0                         1                         2                         3                         4              
    0   E5 68 96 84 BB F3 76 82   EE 79 50 06 FB 4E 07 DB   A5 8D 11 C3 12 32 DF 57   9B C8 91 AB 77 6B 62 71   61 D2 4A 2A 59 BB BE E2   
    1   8D DC FF C5 4D 27 46 90   21 6D DE AC B9 2F 45 3E   B5 AF 4D 40 3D 59 E0 D2   00 EE 2F 85 9E AE 88 CB   37 76 B4 9D C8 E8 01 5B   
    2   07 CA 68 9F 69 27 C5 71   D5 22 67 93 71 FE 3C F2   54 4D D8 4C 9F 2D AC 1F   28 E0 89 94 43 03 A5 21   BA 2F 42 03 25 D7 28 BD   
    3   D4 80 A9 3F CC F1 63 2C   9B E5 4A FF B8 C7 BF 88   7B BC BA 8F 8B B6 CD 54   00 E5 45 0C AF 87 21 84   FD E0 8A 1C AD BF 8E EF   
    4   3D 70 59 E3 5A DE F9 D5   67 54 05 32 BB FA 57 6A   7B C2 19 49 E6 0E B6 D9   4F C6 2C 91 3F 38 F1 5A   AC DD D6 59 4A FC 0A 37   
    -----------------------------------------------------------------------------------------------------------------------------------
    digest: E5 68 96 84 BB F3 76 82 8D DC FF C5 4D 27 46 90 07 CA 68 9F 69 27 C5 71 D4 80 A9 3F CC F1 63 2C
    e5689684bbf376828ddcffc54d27469007ca689f6927c571d480a93fccf1632c


