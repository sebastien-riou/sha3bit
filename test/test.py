import hashlib
import logging
import re
from pathlib import Path

from bitarray import bitarray
from pysatl import Utils

import sha3bit
from sha3bit import sha3_256, shake_128


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
            # print(Utils.hexstr(block))
            expected.update(block)
            dut.update(block)
        assert expected.digest() == dut.digest()

    for seed_byte in range(0, n_seeds):
        for msg_bitlen in range(0, max_length, 8):
            seed = bytearray([seed_byte])
            logging.info('\ntest msg_bitlen: %d' % msg_bitlen)
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
            # print(Utils.hexstr(block))
            expected.update(block)
            dut.update(block)
        assert expected.digest(output_size) == dut.digest(output_size)

    for seed_byte in range(0, n_seeds):
        output_size = 17 + seed_byte
        for msg_bitlen in range(0, max_length, 8):
            seed = bytearray([seed_byte])
            logging.info('\ntest msg_bitlen: %d, output_size: %d' % (msg_bitlen, output_size))
            check_against_hashlib(seed, msg_bitlen, output_size)
            logging.info('\n')


def check(msg, bitlen, sig, *, seclevel=256):
    m = sha3bit.sha3(seclevel)()
    if isinstance(msg, str):
        msg = msg.encode('ascii')
    descr = 'msg      = ' + Utils.hexstr(msg) + '\n'
    descr += 'bitlen   = %d\n' % bitlen
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
    descr = 'msg      = ' + Utils.hexstr(msg) + '\n'
    descr += 'bitlen   = %d\n' % bitlen
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
        print('seclevel = %d' % seclevel)
        for tv_file in ['SHA3_%dShortMsg.rsp' % seclevel, 'SHA3_%dLongMsg.rsp' % seclevel]:
            tv_path = resource_path.joinpath(tv_file)
            with open(tv_path) as f:
                for line in f:
                    if line.startswith('Len'):
                        bitlen = int(re.search(r'Len = (.+)', line).group(1))
                    if line.startswith('Msg'):
                        msg = Utils.ba(re.search(r'Msg = (.+)', line).group(1))
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
        print('seclevel = %d' % seclevel)
        for tv_file in ['SHAKE%dShortMsg.rsp' % seclevel, 'SHAKE%dLongMsg.rsp' % seclevel]:
            tv_path = resource_path.joinpath(tv_file)
            with open(tv_path) as f:
                for line in f:
                    if line.startswith('Len'):
                        bitlen = int(re.search(r'Len = (.+)', line).group(1))
                    if line.startswith('Msg'):
                        msg = Utils.ba(re.search(r'Msg = (.+)', line).group(1))
                        if bitlen == 0:
                            msg = bytes(0)
                    if line.startswith('Output'):
                        md = re.search(r'Output = (.+)', line).group(1)
                        check_xof(msg, bitlen, md, seclevel=seclevel)


def check_api():
    print('check API')
    msg = msg_generator(bytes(0), 300 * 8)
    expected = hashlib.sha3_256(msg).digest()
    # print(Utils.hexstr(msg))
    # print(Utils.hexstr(expected))
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


if __name__ == '__main__':
    check_api_xof_absorb()
    check_api_xof()
    check_api()
    check_hardcoded_test_vectors()
    check_xof_against_hashlib(n_seeds=3, max_length=1024 * 4)
    check_against_hashlib(n_seeds=3, max_length=1024 * 4)
    check_against_nist_cavp()
    check_xof_against_nist_cavp()
    print('All test PASS')
