import hashlib
import logging
import re
from pathlib import Path

from bitarray import bitarray

import sha3bit
from sha3bit import kangaroo12_128, kangaroo12_256, sha3_256, shake_128, turboshake_128, turboshake_256
from sha3bit.utils import ba, hexstr


def block_generator(seed, msg_bitlen, block_size=136):
    if 0 == msg_bitlen:
        yield bytearray()
    else:
        l2block = hashlib.shake_128().digest(block_size)
        block_bitlen = len(l2block) * 8
        bitlen = 0
        while bitlen + block_bitlen < msg_bitlen:
            yield l2block
            bitlen += block_bitlen
            l2block = hashlib.shake_128().digest(block_size)
        # last block
        last_block_bitlen = msg_bitlen % (block_size * 8)
        if 0 != last_block_bitlen:
            last_block_full_bytelen = (last_block_bitlen + 7) // 8
            l2block = bytearray(l2block[0:last_block_full_bytelen])
            assert len(l2block) == last_block_full_bytelen
            mask = 0xFF & (0xFF << (8 - (msg_bitlen % 8)))
            if 0 != mask:
                l2block[-1] &= mask
        yield l2block


def msg_generator(seed, msg_bitlen):
    o = bytearray()
    for b in block_generator(seed, msg_bitlen):
        o += b
    return o


def check_against_hashlib(n_seeds=3, max_length=1024 * 4):
    print('check against hashlib')

    assert hashlib.sha3_256(b'abc').digest() == sha3_256(b'abc').digest()

    def check_against_hashlib(seed, msg_bitlen):
        expected = hashlib.sha3_256()
        dut = sha3_256()
        for block in block_generator(seed, msg_bitlen, block_size=dut.block_size):
            # print(hexstr(block))
            expected.update(block)
            dut.update(block)
        assert expected.digest() == dut.digest()

    for seed_byte in range(0, n_seeds):
        for msg_bitlen in range(0, max_length, 8):
            seed = bytearray([seed_byte])
            logging.info('\ntest msg_bitlen: %d', msg_bitlen)
            check_against_hashlib(seed, msg_bitlen)
            logging.info('\n')


def check_xof_against_hashlib(n_seeds=3, max_length=1024 * 4):
    print('check against hashlib')
    output_size = 67
    assert hashlib.shake_128(b'abc').digest(output_size) == shake_128(b'abc').digest(output_size)

    # check multiple calls of digest, hashlib return always the same!
    model = hashlib.shake_128()
    dut = shake_128()
    expected = model.digest(output_size)
    result = dut.digest(output_size)
    assert expected == result, f'expected: {expected}, result: {result}'
    expected = model.digest(output_size)
    result = dut.digest(output_size)
    assert expected == result, f'expected: {expected}, result: {result}'

    def check_against_hashlib(seed, msg_bitlen, output_size):
        expected = hashlib.shake_128()
        dut = shake_128()
        for block in block_generator(seed, msg_bitlen, block_size=dut.block_size):
            # print(hexstr(block))
            expected.update(block)
            dut.update(block)
        assert expected.digest(output_size) == dut.digest(output_size)

    for seed_byte in range(0, n_seeds):
        output_size = 17 + seed_byte
        for msg_bitlen in range(0, max_length, 8):
            seed = bytearray([seed_byte])
            logging.info('\ntest msg_bitlen: %d, output_size: %d', msg_bitlen, output_size)
            check_against_hashlib(seed, msg_bitlen, output_size)
            logging.info('\n')


def check(msg, bitlen, sig, *, seclevel=256):
    m = sha3bit.sha3(seclevel)()
    if isinstance(msg, str):
        msg = msg.encode('ascii')
    descr = 'msg      = ' + hexstr(msg) + '\n'
    descr += f'bitlen   = {bitlen}\n'
    descr += 'expected = ' + sig + '\n'
    try:
        m.update(msg, bitlen=bitlen)
        digest = m.hexdigest()
    except Exception as e:
        print(descr)
        raise e
    err_msg = '\n'
    err_msg += descr
    err_msg += 'digest   = ' + digest + '\n'
    assert digest == sig, err_msg


def check_xof(msg, bitlen, sig, *, seclevel=256):
    m = sha3bit.shake(seclevel)()
    if isinstance(msg, str):
        msg = msg.encode('ascii')
    descr = 'msg      = ' + hexstr(msg) + '\n'
    descr += f'bitlen   = {bitlen}\n'
    descr += 'expected = ' + sig + '\n'
    try:
        m.update(msg, bitlen=bitlen)
        digest = m.hexdigest(length=m.seclevel // 8)
    except Exception as e:
        print(descr)
        raise e
    err_msg = '\n'
    err_msg += descr
    err_msg += 'digest   = ' + digest + '\n'
    assert digest == sig, err_msg


def check_hardcoded_test_vectors():
    print('check few minimal hardcoded test vectors')

    tests = [
        {
            'msg': '',
            'bitlen': 0,
            'digest': 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
        },
        {
            'msg': 'a',
            'bitlen': 8,
            'digest': '80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b',
        },
    ]

    for test in tests:
        check(test['msg'], test['bitlen'], test['digest'])


def check_against_nist_cavp():
    print("check against 'short' and 'long' bit oriented test vectors from NIST CAVP")
    # (https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bittestvectors.zip)
    resource_path = Path(__file__).parent
    for seclevel in [224, 256, 384, 512]:
        print(f'seclevel = {seclevel}')
        for tv_file in [f'SHA3_{seclevel}ShortMsg.rsp', f'SHA3_{seclevel}LongMsg.rsp']:
            tv_path = resource_path.joinpath(tv_file)
            with open(tv_path) as f:
                for line in f:
                    if line.startswith('Len'):
                        bitlen = int(re.search(r'Len = (.+)', line).group(1))
                    if line.startswith('Msg'):
                        msg = ba(re.search(r'Msg = (.+)', line).group(1))
                        if bitlen == 0:
                            msg = bytes(0)
                    if line.startswith('MD'):
                        md = re.search(r'MD = (.+)', line).group(1)
                        check(msg, bitlen, md, seclevel=seclevel)


def check_xof_against_nist_cavp():
    print("check against 'short' and 'long' bit oriented test vectors from NIST CAVP")
    # (https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebittestvectors.zip)
    resource_path = Path(__file__).parent
    for seclevel in [128, 256]:
        print(f'seclevel = {seclevel}')
        for tv_file in [f'SHAKE{seclevel}ShortMsg.rsp', f'SHAKE{seclevel}LongMsg.rsp']:
            tv_path = resource_path.joinpath(tv_file)
            with open(tv_path) as f:
                for line in f:
                    if line.startswith('Len'):
                        bitlen = int(re.search(r'Len = (.+)', line).group(1))
                    if line.startswith('Msg'):
                        msg = ba(re.search(r'Msg = (.+)', line).group(1))
                        if bitlen == 0:
                            msg = bytes(0)
                    if line.startswith('Output'):
                        md = re.search(r'Output = (.+)', line).group(1)
                        check_xof(msg, bitlen, md, seclevel=seclevel)


def check_api():
    print('check API')
    msg = msg_generator(bytes(0), 300 * 8)
    expected = hashlib.sha3_256(msg).digest()
    # print(hexstr(msg))
    # print(hexstr(expected))
    assert expected == sha3_256(msg).digest()
    for len1 in range(0, len(msg) * 8):
        dut1 = sha3_256()
        dut1.update(msg[:len1])
        state = dut1.export_state()
        dut2 = sha3_256.import_state(state)
        dut2.update(msg[len1:])
        assert expected == dut2.digest()
    for len1 in range(1, len(msg) * 8):
        dut = sha3_256()
        remaining = len(msg)
        p = 0
        while remaining > 0:
            chunk = msg[p : p + len1]
            dut.update(chunk, bitlen=len(chunk) * 8)
            p += len1
            remaining -= len1
        assert expected == dut.digest()
        state = dut.export_state()
        dut2 = sha3_256.import_state(state)
        assert expected == dut2.digest()
    dut = sha3_256(b'\x00', bitlen=1)
    state = dut.export_state()
    dut2 = sha3_256.import_state(state)
    assert dut2.hexdigest() == '1b2e61923578e35f3b4629e04a0ff3b73daa571ae01130d9c16ef7da7a4cfdc2'

    # an exported state is a snapshot: it is not changed by further use of the instance it comes from,
    # and the instances imported from it are independent of it and of each other
    dut = sha3_256(msg[:200])
    state = dut.export_state()
    dut2 = sha3_256.import_state(state)
    dut3 = sha3_256.import_state(state)
    dut.update(msg[200:280])
    dut2.update(msg[200:])
    assert dut.digest() == hashlib.sha3_256(msg[:280]).digest()
    assert dut2.digest() == hashlib.sha3_256(msg).digest()
    assert dut3.digest() == hashlib.sha3_256(msg[:200]).digest()
    assert sha3_256.import_state(state).digest() == hashlib.sha3_256(msg[:200]).digest()

    try:
        sha3bit.sha3(1)
    except ValueError as e:
        assert str(e) == 'seclevel=1, it must be in [224, 256, 384, 512]'
    else:
        raise AssertionError('sha3(1) should fail')


def check_api_xof():
    print('check API for SHAKE: squeez')
    # check many ways to squeez output are equivalent
    output_size = 200
    expected = hashlib.shake_128().digest(output_size)
    for i in range(1, output_size - 4):
        for j in range(i + 2, output_size - 2):
            expected0 = expected[0:i]
            expected1 = expected[i:j]
            expected2 = expected[j:]
            dut = shake_128()
            r0 = dut.squeez(len(expected0))
            assert r0 == expected0
            r1 = dut.squeez(len(expected1))
            assert r1 == expected1
            r2 = dut.squeez(len(expected2))
            assert r2 == expected2

    # export/import after squeez, with verbose enabled
    expected = hashlib.shake_128(b'abc').digest(20)
    dut = shake_128(b'abc', verbose=True)
    assert dut.squeez(10) == expected[0:10]
    dut2 = shake_128.import_state(dut.export_state())
    assert dut2.squeez(10) == expected[10:]

    # hexsqueez consumes the output like squeez
    dut = shake_128(b'abc')
    assert dut.hexsqueez(10) == expected[0:10].hex()
    assert dut.hexsqueez(10) == expected[10:].hex()

    # an exported state is a snapshot, also while squeezing
    expected = hashlib.shake_128(b'abc').digest(500)
    dut = shake_128(b'abc')
    dut.squeez(5)
    state = dut.export_state()
    dut2 = shake_128.import_state(state)
    assert dut.squeez(300) == expected[5:305]
    assert dut2.squeez(300) == expected[5:305]
    assert shake_128.import_state(state).squeez(495) == expected[5:]


def check_api_xof_absorb():
    print('check API for SHAKE: absorb')
    # check many ways to absorb input are equivalent
    output_size = 16
    input_bitlen = 1600 + 40
    msg = msg_generator(0, input_bitlen)
    msgbits = bitarray(endian='little')
    msgbits.frombytes(msg)
    expected = hashlib.shake_128(msg).digest(output_size)
    dut = shake_128(msg[0:2])
    dut.update(msg[2:])
    assert expected == dut.digest(output_size)
    assert expected == shake_128(msg, verbose=False).digest(output_size)
    for i in range(1500, input_bitlen - 18):
        for j in range(i + 2, i + 16):
            m0 = msgbits[0:i]
            m1 = msgbits[i:j]
            m2 = msgbits[j:]
            dut = shake_128(verbose=False)
            dut.update(m0.tobytes(), bitlen=len(m0))
            dut.update(m1.tobytes(), bitlen=len(m1))
            dut.update(m2.tobytes(), bitlen=len(m2))
            assert dut.digest(output_size) == expected


# round constants of Keccak-f[1600], from FIPS 202
KECCAK_RC = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]


def check_f1600_rounds():
    print('check f1600 with reduced number of rounds')
    f1600 = sha3bit.Keccak.f1600
    lane_bytes = hashlib.shake_128(b'f1600').digest(200)
    lane_values = [int.from_bytes(lane_bytes[8 * i : 8 * i + 8], 'little') for i in range(25)]
    lanes = [[lane_values[x + 5 * y] for y in range(5)] for x in range(5)]

    assert f1600(lanes, nrounds=24) == f1600(lanes)

    # a single round applied to the all-zero state only adds the round constant
    zero = [[0] * 5 for _ in range(5)]
    expected = [[0] * 5 for _ in range(5)]
    expected[0][0] = KECCAK_RC[23]
    assert f1600(zero, nrounds=1) == expected

    # Keccak-p[1600, nrounds] is the last nrounds rounds of Keccak-f[1600]:
    # build each round from the last one by fixing the round constant
    def keccak_round(lanes, round_index):
        out = f1600(lanes, nrounds=1)
        out[0][0] ^= KECCAK_RC[23] ^ KECCAK_RC[round_index]
        return out

    for nrounds in range(1, 25):
        expected = lanes
        for round_index in range(24 - nrounds, 24):
            expected = keccak_round(expected, round_index)
        assert f1600(lanes, nrounds=nrounds) == expected, f'nrounds={nrounds}'

    # TurboSHAKE128(M=empty, D=0x1F, 32 bytes) from RFC 9861, it uses Keccak-p[1600, 12]
    state = [[0] * 5 for _ in range(5)]
    state[0][0] = 0x1F  # byte 0: domain separation byte
    state[0][4] = 0x80 << 56  # byte 167, last byte of the 168 bytes rate: padding
    state = f1600(state, nrounds=12)
    out = b''.join(state[i][0].to_bytes(8, 'little') for i in range(4))
    assert out.hex() == '1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c'

    for nrounds in [0, 25, -1]:
        try:
            f1600(lanes, nrounds=nrounds)
        except ValueError:
            pass
        else:
            raise AssertionError(f'nrounds={nrounds} should fail')


def ptn(n):
    """pattern used by RFC 9861 test vectors"""
    return bytes(i % 251 for i in range(n))


def check_keccak_rounds():
    print('check Keccak with reduced number of rounds')
    # TurboSHAKE and KangarooTwelve use Keccak-p[1600, 12]. Keccak's suffix holds the bits of
    # TurboSHAKE's domain separation byte D, LSB first: D=0x1F -> '11111', D=0x07 -> '111', D=0x06 -> '011'

    def turboshake(capacity, suffix, msg, outlen):
        k = sha3bit.Keccak(capacity, suffix, nrounds=12)
        k.absorb(msg)
        return bytes(k.squeez(outlen))

    # from RFC 9861
    assert turboshake(256, '11111', b'', 32).hex() == '1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c'
    assert turboshake(512, '11111', b'', 64).hex() == (
        '367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db'
        + '11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0'
    )
    # KangarooTwelve(M=empty, C=empty, 32 bytes) is TurboSHAKE128(M=00, D=0x07, 32 bytes)
    assert (
        turboshake(256, '111', b'\x00', 32).hex() == '1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5'
    )

    # multi-block input and output, computed with pycryptodome 3.23
    msg = ptn(17**2)
    out = turboshake(256, '11111', msg, 200)
    assert out[-32:].hex() == '39aef6a1382064f695626e98019f01d8864725e05cb4c4089f3b968c92575ef5'
    assert turboshake(512, '011', msg, 200)[-32:].hex() == (
        '6fbdd721effb9e1b89fd6dd00674ad115f2309b3cce584dc400554203732f057'
    )

    # export/import keeps the number of rounds, while absorbing and while squeezing
    k = sha3bit.Keccak(256, '11111', nrounds=12)
    k.absorb(msg[:100])
    k = sha3bit.Keccak.import_state(k.export_state())
    assert k.nrounds == 12
    k.absorb(msg[100:])
    result = bytes(k.squeez(50))
    k = sha3bit.Keccak.import_state(k.export_state())
    assert k.nrounds == 12
    result += bytes(k.squeez(150))
    assert result == out

    # states exported by older versions have no 'nrounds' entry
    k = sha3bit.Keccak(256, '11111')
    k.absorb(b'a')
    state = k.export_state()
    del state['nrounds']
    k = sha3bit.Keccak.import_state(state)
    assert k.nrounds == 24
    k.absorb(b'bc')
    assert bytes(k.squeez(32)) == hashlib.shake_128(b'abc').digest(32)

    for nrounds in [0, 25, -1]:
        try:
            sha3bit.Keccak(256, '11111', nrounds=nrounds)
        except ValueError:
            pass
        else:
            raise AssertionError(f'nrounds={nrounds} should fail')


def check_turboshake():
    print('check TurboSHAKE')
    # from RFC 9861
    assert turboshake_128(b'').hexdigest(32) == '1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c'
    assert turboshake_256(b'').hexdigest(64) == (
        '367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db'
        + '11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0'
    )
    # multi-block input and output, computed with pycryptodome 3.23
    msg = ptn(17**2)
    expected = turboshake_128(msg).digest(200)
    assert expected[-32:].hex() == '39aef6a1382064f695626e98019f01d8864725e05cb4c4089f3b968c92575ef5'
    assert turboshake_256(msg, domain=0x06).digest(200)[-32:].hex() == (
        '6fbdd721effb9e1b89fd6dd00674ad115f2309b3cce584dc400554203732f057'
    )

    # export/import keeps domain and number of rounds, while absorbing and while squeezing
    dut = turboshake_128()
    dut.update(msg[:100])
    dut = turboshake_128.import_state(dut.export_state())
    dut.update(msg[100:])
    out = bytes(dut.squeez(50))
    dut = turboshake_128.import_state(dut.export_state())
    out += bytes(dut.squeez(150))
    assert out == expected
    dut = turboshake_256(domain=0x06)
    dut.update(msg[:100])
    dut = turboshake_256.import_state(dut.export_state())
    dut.update(msg[100:])
    assert dut.digest(200) == turboshake_256(msg, domain=0x06).digest(200)

    # a message of 8 * k + n bits is followed by the bits of D:
    # with D=0x01 this is the same as the first k bytes followed by D' = last n bits | 1 << n
    for n in range(1, 7):
        for tail in range(1 << n):
            dut = turboshake_128(msg[:30] + bytes([tail]), bitlen=8 * 30 + n, domain=0x01)
            assert dut.digest(20) == turboshake_128(msg[:30], domain=tail | (1 << n)).digest(20), (n, tail)

    # hexsqueez consumes the output like squeez
    dut = turboshake_128(msg)
    assert dut.hexsqueez(100) + dut.hexsqueez(100) == expected.hex()

    for domain in [0x00, 0x80]:
        try:
            turboshake_128(domain=domain)
        except ValueError:
            pass
        else:
            raise AssertionError(f'domain={domain} should fail')


def check_kangaroo12():
    print('check KangarooTwelve')
    # from RFC 9861, as listed in the tests of the kangarootwelve Rust crate (github.com/itzmeanjan/kangarootwelve)
    rfc_vectors = [
        (kangaroo12_128, b'', b'', '1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5'),
        (
            kangaroo12_128,
            b'',
            b'',
            '1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e54269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71',
        ),
        (kangaroo12_128, ptn(1), b'', '2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f'),
        (kangaroo12_128, ptn(17), b'', '6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888'),
        (kangaroo12_128, ptn(17**2), b'', '0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c'),
        (kangaroo12_128, ptn(17**3), b'', 'cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0'),
        (kangaroo12_128, ptn(17**4), b'', '8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe'),
        (kangaroo12_128, b'', ptn(1), 'fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583'),
        (kangaroo12_128, b'\xff', ptn(41), 'd848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4'),
        (kangaroo12_128, b'\xff' * 3, ptn(41**2), 'c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74'),
        (kangaroo12_128, b'\xff' * 7, ptn(41**3), '75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf'),
        (kangaroo12_128, ptn(8191), b'', '1b577636f723643e990cc7d6a659837436fd6a103626600eb8301cd1dbe553d6'),
        (kangaroo12_128, ptn(8192), b'', '48f256f6772f9edfb6a8b661ec92dc93b95ebd05a08a17b39ae3490870c926c3'),
        (kangaroo12_128, ptn(8192), ptn(8189), '3ed12f70fb05ddb58689510ab3e4d23c6c6033849aa01e1d8c220a297fedcd0b'),
        (kangaroo12_128, ptn(8192), ptn(8190), '6a7c1b6a5cd0d8c9ca943a4a216cc64604559a2ea45f78570a15253d67ba00ae'),
        (
            kangaroo12_256,
            b'',
            b'',
            'b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9',
        ),
        (
            kangaroo12_256,
            b'',
            b'',
            'b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9b0925319d8ea1e121a609821ec19efea89e6d08daee1662b69c840289f188ba860f55760b61f82114c030c97e5178449608ccd2cd2d919fc7829ff69931ac4d0',
        ),
        (
            kangaroo12_256,
            ptn(1),
            b'',
            '0d005a194085360217128cf17f91e1f71314efa5564539d444912e3437efa17f82db6f6ffe76e781eaa068bce01f2bbf81eacb983d7230f2fb02834a21b1ddd0',
        ),
        (
            kangaroo12_256,
            ptn(17),
            b'',
            '1ba3c02b1fc514474f06c8979978a9056c8483f4a1b63d0dccefe3a28a2f323e1cdcca40ebf006ac76ef0397152346837b1277d3e7faa9c9653b19075098527b',
        ),
        (
            kangaroo12_256,
            ptn(17**2),
            b'',
            'de8ccbc63e0f133ebb4416814d4c66f691bbf8b6a61ec0a7700f836b086cb029d54f12ac7159472c72db118c35b4e6aa213c6562caaa9dcc518959e69b10f3ba',
        ),
        (
            kangaroo12_256,
            ptn(17**3),
            b'',
            '647efb49fe9d717500171b41e7f11bd491544443209997ce1c2530d15eb1ffbb598935ef954528ffc152b1e4d731ee2683680674365cd191d562bae753b84aa5',
        ),
        (
            kangaroo12_256,
            ptn(17**4),
            b'',
            'b06275d284cd1cf205bcbe57dccd3ec1ff6686e3ed15776383e1f2fa3c6ac8f08bf8a162829db1a44b2a43ff83dd89c3cf1ceb61ede659766d5ccf817a62ba8d',
        ),
        (
            kangaroo12_256,
            b'',
            ptn(1),
            '9280f5cc39b54a5a594ec63de0bb99371e4609d44bf845c2f5b8c316d72b159811f748f23e3fabbe5c3226ec96c62186df2d33e9df74c5069ceecbb4dd10eff6',
        ),
        (
            kangaroo12_256,
            b'\xff',
            ptn(41),
            '47ef96dd616f200937aa7847e34ec2feae8087e3761dc0f8c1a154f51dc9ccf845d7adbce57ff64b639722c6a1672e3bf5372d87e00aff89be97240756998853',
        ),
        (
            kangaroo12_256,
            b'\xff' * 3,
            ptn(41**2),
            '3b48667a5051c5966c53c5d42b95de451e05584e7806e2fb765eda959074172cb438a9e91dde337c98e9c41bed94c4e0aef431d0b64ef2324f7932caa6f54969',
        ),
        (
            kangaroo12_256,
            b'\xff' * 7,
            ptn(41**3),
            'e0911cc00025e1540831e266d94add9b98712142b80d2629e643aac4efaf5a3a30a88cbf4ac2a91a2432743054fbcc9897670e86ba8cec2fc2ace9c966369724',
        ),
        (
            kangaroo12_256,
            ptn(8191),
            b'',
            '3081434d93a4108d8d8a3305b89682cebedc7ca4ea8a3ce869fbb73cbe4a58eef6f24de38ffc170514c70e7ab2d01f03812616e863d769afb3753193ba045b20',
        ),
        (
            kangaroo12_256,
            ptn(8192),
            b'',
            'c6ee8e2ad3200c018ac87aaa031cdac22121b412d07dc6e0dccbb53423747e9a1c18834d99df596cf0cf4b8dfafb7bf02d139d0c9035725adc1a01b7230a41fa',
        ),
        (
            kangaroo12_256,
            ptn(8192),
            ptn(8189),
            '74e47879f10a9c5d11bd2da7e194fe57e86378bf3c3f7448eff3c576a0f18c5caae0999979512090a7f348af4260d4de3c37f1ecaf8d2c2c96c1d16c64b12496',
        ),
        (
            kangaroo12_256,
            ptn(8192),
            ptn(8190),
            'f4b5908b929ffe01e0f79ec2f21243d41a396b2e7303a6af1d6399cd6c7a0a2dd7c4f607e8277f9c9b1cb4ab9ddc59d4b92d1fc7558441f1832c3279a4241b8b',
        ),
    ]
    for cls, msg, custom, expected in rfc_vectors:
        assert cls(msg, custom=custom).hexdigest(len(expected) // 2) == expected, (cls, len(msg), len(custom))

    # Not covered by RFC 9861, cross-checked with the kangarootwelve Rust crate 0.1.3 and noble-hashes 2.4.0
    # (and cloudflare/circl 1.6.5 for KT128):
    # empty message, the customization string alone is longer than one chunk.
    # pycryptodome 3.23 gets KT128 wrong in this case, unless update() is called
    assert kangaroo12_128(custom=ptn(8191)).hexdigest(32) == (
        '70c43af10d873c81310b8f9af5945f3ddd9298a6f83b35792b23778b79a29a3f'
    )
    assert kangaroo12_256(custom=ptn(8191)).hexdigest(64) == (
        '19eb2215e82f6b2087cb8485651e233c2fa4890d2d3715a3addb89f3690da3cc'
        + 'e0ca5af12c135ed2bb8dec5fc51926653368caf5c38d90e269232a435e85aa3e'
    )
    # 4 chunks, last 32 bytes of 200 bytes of output
    msg = ptn(3 * 8192 + 17)
    custom = ptn(41)
    four_chunks = [
        (kangaroo12_128, 'f367828787de32e2711d9c4378851d9a78c7ffe9a7efcd45eef6936e56e2f793'),
        (kangaroo12_256, '2b67604f2123fe6071742ccc445c79b53febe7438d356d23eeee4543ad31d497'),
    ]
    for cls, expected_end in four_chunks:
        expected = cls(msg, custom=custom).digest(200)
        assert expected[-32:].hex() == expected_end, cls
        assert cls(msg, custom=custom).digest(200) == expected  # digest does not change the state

        # any split of the message and export/import at any time give the same result
        for step in [1000, 8191, 8192, 8193]:
            dut = cls(custom=custom)
            for p in range(0, len(msg), step):
                dut.update(msg[p : p + step])
                dut = cls.import_state(dut.export_state())
            out = bytes(dut.squeez(50))
            dut = cls.import_state(dut.export_state())
            out += bytes.fromhex(dut.hexsqueez(150))
            assert out == expected, (cls, step)

        # an exported state is a snapshot, not changed by further use of the instance it comes from
        dut = cls(msg[:10000], custom=custom)
        state = dut.export_state()
        dut.update(msg[10000:])
        assert dut.digest(200) == expected
        assert cls.import_state(state).digest(32) == cls(msg[:10000], custom=custom).digest(32)

        dut = cls(b'abc')
        dut.squeez(1)
        try:
            dut.update(b'd')
        except Exception:  # noqa: S110
            pass
        else:
            raise AssertionError('update after squeez should fail')


if __name__ == '__main__':
    check_f1600_rounds()
    check_keccak_rounds()
    check_turboshake()
    check_kangaroo12()
    check_api_xof_absorb()
    check_api_xof()
    check_api()
    check_hardcoded_test_vectors()
    check_xof_against_hashlib(n_seeds=3, max_length=1024 * 4)
    check_against_hashlib(n_seeds=3, max_length=1024 * 4)
    check_against_nist_cavp()
    check_xof_against_nist_cavp()
    print('All test PASS')
