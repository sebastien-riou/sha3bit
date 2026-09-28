import binascii
import copy
import logging

from bitarray import bitarray

from sha3bit.utils import hexstr


class BitFiFo:
    def __init__(self, bitlen, full_threshold=None):
        self.buf = bitarray(endian='little')
        self.bitlen = bitlen
        if full_threshold is None:
            self.full_threshold = bitlen
        else:
            self.full_threshold = full_threshold

    def level(self):
        return len(self.buf)

    def full(self):
        return len(self.buf) >= self.full_threshold

    def empty(self):
        return 0 == len(self.buf)

    def only_full_bytes(self):
        return 0 == len(self.buf) % 8

    def remaining_before_full(self):
        return self.full_threshold - len(self.buf)

    def remaining_capacity(self):
        return self.bitlen - len(self.buf)

    def push(self, data):
        bitlen = len(data)
        overflow = bitlen - self.remaining_capacity()
        if overflow > 0:
            raise BufferError(f'Data to big to fit in the buffer by {overflow} bits')
        self.buf += data

    def push_bytes(self, data, bitlen=None):
        data_bits = bitarray(endian='little')
        data_bits.frombytes(data)
        if bitlen is not None:
            data_bits = data_bits[0:bitlen]
        self.push(data_bits)

    def push_consume_bytes(self, data, bitlen=None):
        data_bits = bitarray(endian='little')
        data_bits.frombytes(data)
        if bitlen is not None:
            bits_to_push = data_bits[0:bitlen]
            remaining_bits = data_bits[bitlen:]
        self.push(bits_to_push)
        return remaining_bits.tobytes()

    def pop(self, bitlen):
        underflow = bitlen - len(self.buf)
        if underflow > 0:
            raise BufferError(f'Not enough data in the buffer, underflow by {underflow} bits')
        out = self.buf[0:bitlen]
        b = bitarray(endian='little')
        b += self.buf[bitlen:]
        self.buf = b
        return out

    def pop_bytes(self, bitlen):
        out = self.pop(bitlen)
        return out.tobytes()

    def tobytes(self):
        return self.buf.tobytes()


class Keccak:
    def __init__(self, capacity, suffix: str, *, verbose: bool = False, nrounds: int = 24):
        """SHA3-Keccak implementation supporting bit granularity for message input length.
        This implement only the variant describe in SHA3 standard.
        nrounds is the number of rounds of the permutation, see f1600.
        """
        if (capacity % 8) != 0:
            raise ValueError(f'capacity is not a multiple of 8: {capacity}')
        if capacity > 1600:
            raise ValueError('capacity > 1600')
        if not 1 <= nrounds <= 24:
            raise ValueError(f'nrounds={nrounds}, it must be in [1, 24]')
        self.nrounds = nrounds
        self.suffix = suffix
        self.capacity = capacity
        self.rate = 1600 - self.capacity
        self.rate_bytes = self.rate // 8
        self.state = [[0] * 5 for i in range(5)]
        self.buf = BitFiFo(bitlen=self.rate + 8, full_threshold=self.rate)
        self._verbose = verbose
        self.finalized = False

    @staticmethod
    def import_state(state):
        """Initialize an instance from an exported state"""
        capacity = state['capacity']
        suffix = state['suffix']
        finalized = state['finalized']
        verbose = state['verbose']
        nrounds = state.get('nrounds', 24)  # states exported by older versions have no 'nrounds' entry
        if verbose:
            logging.info('importing state:')
            logging.info('  capacity = %d', state['capacity'])
            logging.info('  state:  ' + Keccak._state_str(state['state']))
            if state['finalized']:
                logging.info('  finalized')
            else:
                logging.info('  cache:  ' + hexstr(state['cache']))
                logging.info('  bitlen = %d', state['bitlen'])
        out = Keccak(capacity, suffix, verbose=verbose, nrounds=nrounds)
        out.state = [list(lane_column) for lane_column in state['state']]
        out.finalized = finalized
        if finalized:
            out.buf = bytearray(state['cache'])
        else:
            out.buf.push_bytes(state['cache'], state['bitlen'])
        return out

    def export_state(self):
        """Export current state to a dict"""
        state = {}
        state['verbose'] = self._verbose
        state['capacity'] = self.capacity
        state['suffix'] = self.suffix
        state['nrounds'] = self.nrounds
        state['finalized'] = self.finalized
        state['state'] = [list(lane_column) for lane_column in self.state]
        if state['finalized']:
            state['cache'] = bytes(self.buf)
        else:
            state['cache'] = self.buf.tobytes()
            state['bitlen'] = self.buf.level()
        if self._verbose:
            logging.info('exporting current state:')
            logging.info('  capacity = %d', state['capacity'])
            logging.info('  state:  ' + Keccak._state_str(self.state))
            logging.info('  cache:  ' + hexstr(state['cache']))
            if state['finalized']:
                logging.info('  finalized')
            else:
                logging.info('  bitlen = %d', state['bitlen'])
        return state

    def _process_block(self, block):
        nlanes = self.rate_bytes // 8
        input_bytes = bytearray(self.rate_bytes)
        input_bytes[0 : len(block)] = block
        input_lanes = [[0] * 5 for i in range(5)]
        for i in range(nlanes):
            lane = int.from_bytes(input_bytes[i * 8 : i * 8 + 8], byteorder='little')
            y = i // 5
            x = i - 5 * y
            input_lanes[x][y] = lane
            self.state[x][y] ^= lane
        if self._verbose:
            logging.info('process block:\n' + Keccak._state_str(input_lanes, limit=nlanes))
        self.state = Keccak.f1600(self.state, verbose=self._verbose, nrounds=self.nrounds)

    def absorb(self, data, bitlen=None):
        """Update the sponge object with the bytes in data. Repeated calls
        are equivalent to a single call with the concatenation of all
        the arguments.
        """
        if not data:
            return
        if bitlen is None:
            bitlen = len(data) * 8
        if not self.buf.empty():
            to_consume = min(bitlen, self.buf.remaining_before_full())
            data = self.buf.push_consume_bytes(data, to_consume)
            bitlen -= to_consume
            if self.buf.full():
                r = self.buf.pop_bytes(self.rate)
                self._process_block(r)
        while bitlen >= self.rate:  # process all full blocks directly from input
            # assert self.buf.empty() # valid assertion but we remove it to please RUFF linter
            self._process_block(data[0 : self.rate_bytes])
            bitlen -= self.rate
            data = data[self.rate_bytes :]
        if bitlen > 0:  # last block is a partial block, buffer it
            self.buf.push_bytes(data, bitlen)

    def _finalize(self) -> None:
        if self.finalized:
            raise Exception('Already finalized')
        self.buf.push(bitarray(self.suffix, endian='little'))
        if self.buf.full():
            r = self.buf.pop_bytes(self.rate)
            self._process_block(r)
        data = self.buf.tobytes()
        block = bytearray(self.rate_bytes)
        block[0 : len(data)] = data
        block[-1] ^= 0x80
        self._process_block(block)
        self._format_output()
        self.finalized = True

    def _format_output(self):
        buf = bytearray()
        nlanes = self.rate_bytes // 8
        for i in range(nlanes):
            y = i // 5
            x = i - 5 * y
            buf += self.state[x][y].to_bytes(8, byteorder='little')
        self.buf = buf

    def squeez(self, bytelen):
        """Squeez the sponge."""
        if not self.finalized:
            self._finalize()
        out = bytearray()
        remaining = bytelen
        while remaining > 0:
            if 0 == len(self.buf):
                self.state = Keccak.f1600(self.state, verbose=self._verbose, nrounds=self.nrounds)
                self._format_output()
            size = min(remaining, len(self.buf))
            out += self.buf[0:size]
            self.buf = self.buf[size:]
            remaining -= size
        return out

    @staticmethod
    def _rol64(a, n):
        return ((a >> (64 - (n % 64))) + (a << (n % 64))) % (1 << 64)

    @staticmethod
    def f1600(lanes, *, verbose: bool = False, nrounds: int = 24) -> list[list[int]]:
        """SHA3 f function. lanes must be a list of 5 list of 5 int.
        nrounds < 24 gives the reduced round permutation Keccak-p[1600, nrounds] defined in FIPS 202:
        only the last nrounds rounds are applied (round indexes 24 - nrounds to 23).
        """
        if not 1 <= nrounds <= 24:
            raise ValueError(f'nrounds={nrounds}, it must be in [1, 24]')
        if verbose:
            logging.info('f1600 input:\n' + Keccak._state_str(lanes))
        first_round = 24 - nrounds
        r = 1
        for _ in range(7 * first_round):  # skip the round constants of the rounds not applied
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
        for _round in range(first_round, 24):
            # θ
            c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
            d = [c[(x + 4) % 5] ^ Keccak._rol64(c[(x + 1) % 5], 1) for x in range(5)]
            lanes = [[lanes[x][y] ^ d[x] for y in range(5)] for x in range(5)]
            if verbose:
                logging.debug('new round\nc:  %s', Keccak._lane_list_str(c))
                logging.debug('d:  %s', Keccak._lane_list_str(d))
                logging.debug('state after round %d θ:\n%s', _round, Keccak._state_str(lanes))

            # p and π
            x, y = (1, 0)
            current = lanes[x][y]
            for t in range(24):
                x, y = (y, (2 * x + 3 * y) % 5)
                current, lanes[x][y] = (lanes[x][y], Keccak._rol64(current, (t + 1) * (t + 2) // 2))
            if verbose:
                logging.debug('state after round %d p and π:\n%s', _round, Keccak._state_str(lanes))

            # χ
            for y in range(5):
                s = [lanes[x][y] for x in range(5)]
                for x in range(5):
                    lanes[x][y] = s[x] ^ ((~s[(x + 1) % 5]) & s[(x + 2) % 5])
            if verbose:
                logging.debug('state after round %d χ:\n%s', _round, Keccak._state_str(lanes))

            # i
            if verbose:
                logging.debug('lanes[0][0]=%s', Keccak._lane_str(lanes[0][0]))
            for j in range(7):
                r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
                if verbose:
                    logging.debug('j=%d, r=%d', j, r)
                if r & 2:
                    lanes[0][0] = lanes[0][0] ^ (1 << ((1 << j) - 1))
                    if verbose:
                        logging.debug('lanes[0][0]=%s', Keccak._lane_str(lanes[0][0]))

            if verbose:
                if _round == 23:
                    logging.info('f1600 output:\n%s\n%s', Keccak._state_str(lanes), '-' * 131)
                else:
                    logging.debug('state after round %d completion\n%s', _round, Keccak._state_str(lanes))
        return lanes

    @staticmethod
    def _lane_str(lane):
        return hexstr(lane.to_bytes(8, 'little'))

    @staticmethod
    def _lane_list_str(lanes, lane_sep='   '):
        out = ''
        for lane in lanes:
            out += hexstr(lane.to_bytes(8, 'little')) + lane_sep
        return out

    @staticmethod
    def _state_str(lanes, limit=25):
        lane_size = 8
        lane_char_width = lane_size * 2 + lane_size - 1
        lane_sep = '   '
        out = ' ' + lane_sep
        for x in range(5):
            out += f'{x:^ {lane_char_width}}' + lane_sep
        for x in range(5):
            out += f'\n{x}'
            out += lane_sep
            for y in range(5):
                if x + 5 * y < limit:
                    out += Keccak._lane_str(lanes[x][y]) + lane_sep
        return out


class shake_128:
    _suffix = '11111'
    seclevel = 128

    def __init__(self, m=None, *, bitlen=None, verbose=False):
        """SHAKE implementation supporting bit granularity for message input length.
        API is the same as hashlib + export_state / import_state.
        """
        capacity = self.seclevel * 2
        self.digest_size = self.seclevel // 8
        self.block_size = (1600 - capacity) // 8
        self._h = Keccak(capacity=capacity, suffix=self._suffix, verbose=verbose)
        self.update(m, bitlen=bitlen)

    def export_state(self):
        """Export current state to a dict"""
        out = self._h.export_state()
        return out

    @classmethod
    def import_state(cls, state):
        """Initialize an instance from an exported state"""
        o = cls()
        o._h = Keccak.import_state(state)
        return o

    def update(self, m, *, bitlen=None):
        """Update the hash object with the bytes in m. Repeated calls
        are equivalent to a single call with the concatenation of all
        the arguments.
        """
        self._h.absorb(m, bitlen)

    def digest(self, length):
        """Return the digest of the bytes passed to the update() method
        so far as a bytes object.
        """
        bu = copy.deepcopy(self._h)
        out = self._h.squeez(length)
        self._h = bu
        return bytes(out)

    def hexdigest(self, length):
        """Like digest() except the digest is returned as a string
        of double length, containing only hexadecimal digits.
        """
        return binascii.hexlify(self.digest(length)).decode('ascii')

    def squeez(self, length):
        """Squeez the sponge. Unlike digest(), consecutive calls do
        not return same values.
        """
        return self._h.squeez(length)

    def hexsqueez(self, length):
        """Like squeez() except the bytes are returned as a string
        of double length, containing only hexadecimal digits.
        """
        return binascii.hexlify(self.squeez(length)).decode('ascii')


class shake_256(shake_128):
    seclevel = 256


class turboshake_128(shake_128):
    seclevel = 128

    def __init__(self, m=None, *, bitlen=None, domain=0x1F, verbose=False):
        """TurboSHAKE implementation (RFC 9861) supporting bit granularity for message input length.
        domain is the domain separation byte D, it must be in [0x01, 0x7F].
        A message which is not a whole number of bytes is followed by the bits of D, like in SHAKE.
        API is the same as shake_128.
        """
        if not 0x01 <= domain <= 0x7F:
            raise ValueError(f'domain=0x{domain:02X}, it must be in [0x01, 0x7F]')
        capacity = self.seclevel * 2
        self.digest_size = self.seclevel // 8
        self.block_size = (1600 - capacity) // 8
        # bits of D, LSB first, up to its last 1 which is also the first bit of the padding
        suffix = bin(domain)[2:][::-1]
        self._h = Keccak(capacity=capacity, suffix=suffix, verbose=verbose, nrounds=12)
        self.update(m, bitlen=bitlen)


class turboshake_256(turboshake_128):
    seclevel = 256


def _length_encode(x):
    """length_encode() from RFC 9861: x as big endian bytes without leading zeros, then the number of those bytes"""
    b = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
    return b + bytes([len(b)])


class kangaroo12_128:
    seclevel = 128
    _turboshake = turboshake_128
    _chunk_size = 8192
    _cv_size = 32

    def __init__(self, m=None, *, custom=b'', verbose=False):
        """KangarooTwelve implementation (KT128 and KT256 in RFC 9861).
        custom is the customization string C.
        The input length has byte granularity: bitlen is not supported.
        API is the same as shake_128 + custom.
        """
        self.digest_size = self.seclevel // 8
        self.block_size = (1600 - self.seclevel * 2) // 8
        self._custom = bytes(custom)
        self._verbose = verbose
        # S = M || C || length_encode(|C|) is cut in chunks. The first chunk is buffered until we know if
        # S is longer than one chunk: if not, the output is TurboSHAKE(S) otherwise it is a tree hash.
        self._s0 = bytearray()
        self._final = None  # final node of the tree
        self._leaf = None  # leaf being computed, for the chunks after the first one
        self._leaf_len = 0
        self._n_cv = 0  # number of chaining values absorbed by the final node
        self._h = None  # sponge squeezed after finalization
        self.update(m)

    def export_state(self):
        """Export current state to a dict"""
        state = {}
        state['custom'] = self._custom
        state['verbose'] = self._verbose
        state['s0'] = None if self._s0 is None else bytes(self._s0)
        state['final'] = None if self._final is None else self._final.export_state()
        state['leaf'] = None if self._leaf is None else self._leaf.export_state()
        state['leaf_len'] = self._leaf_len
        state['n_cv'] = self._n_cv
        state['h'] = None if self._h is None else self._h.export_state()
        return state

    @classmethod
    def import_state(cls, state):
        """Initialize an instance from an exported state"""
        o = cls(custom=state['custom'], verbose=state['verbose'])
        o._s0 = None if state['s0'] is None else bytearray(state['s0'])
        o._final = None if state['final'] is None else cls._turboshake.import_state(state['final'])
        o._leaf = None if state['leaf'] is None else cls._turboshake.import_state(state['leaf'])
        o._leaf_len = state['leaf_len']
        o._n_cv = state['n_cv']
        o._h = None if state['h'] is None else cls._turboshake.import_state(state['h'])
        return o

    def _new_node(self, m, domain):
        return self._turboshake(m, domain=domain, verbose=self._verbose)

    def _close_leaf(self):
        self._final.update(self._leaf.squeez(self._cv_size))
        self._n_cv += 1
        self._leaf = None
        self._leaf_len = 0

    def _feed(self, data):
        data = bytes(data)
        if self._final is None:
            room = self._chunk_size - len(self._s0)
            self._s0 += data[:room]
            data = data[room:]
            if not data:
                return
            # S is longer than one chunk: start the tree
            self._final = self._new_node(self._s0 + b'\x03' + bytes(7), domain=0x06)
            self._s0 = None
        while data:
            if self._leaf is None:
                self._leaf = self._new_node(None, domain=0x0B)
            size = min(len(data), self._chunk_size - self._leaf_len)
            self._leaf.update(data[:size])
            self._leaf_len += size
            data = data[size:]
            if self._leaf_len == self._chunk_size:
                self._close_leaf()

    def _finalize(self):
        self._feed(self._custom + _length_encode(len(self._custom)))
        if self._final is None:
            self._h = self._new_node(self._s0, domain=0x07)
        else:
            if self._leaf is not None:
                self._close_leaf()
            self._final.update(_length_encode(self._n_cv) + b'\xff\xff')
            self._h = self._final
        self._s0 = None
        self._final = None

    def update(self, m):
        """Update the hash object with the bytes in m. Repeated calls
        are equivalent to a single call with the concatenation of all
        the arguments.
        """
        if self._h is not None:
            raise Exception('Already finalized')
        if m:
            self._feed(m)

    def digest(self, length):
        """Return the digest of the bytes passed to the update() method
        so far as a bytes object.
        """
        return bytes(copy.deepcopy(self).squeez(length))

    def hexdigest(self, length):
        """Like digest() except the digest is returned as a string
        of double length, containing only hexadecimal digits.
        """
        return binascii.hexlify(self.digest(length)).decode('ascii')

    def squeez(self, length):
        """Squeez the sponge. Unlike digest(), consecutive calls do
        not return same values.
        """
        if self._h is None:
            self._finalize()
        return self._h.squeez(length)

    def hexsqueez(self, length):
        """Like squeez() except the bytes are returned as a string
        of double length, containing only hexadecimal digits.
        """
        return binascii.hexlify(self.squeez(length)).decode('ascii')


class kangaroo12_256(kangaroo12_128):
    seclevel = 256
    _turboshake = turboshake_256
    _cv_size = 64


class sha3_224:
    _suffix = '011'
    seclevel = 224

    def __init__(self, m=None, *, bitlen=None, verbose=False):
        """SHA3 implementation supporting bit granularity for message input length.
        API is the same as hashlib + export_state / import_state.
        """
        capacity = self.seclevel * 2
        self.digest_size = self.seclevel // 8
        self.block_size = (1600 - capacity) // 8
        self._verbose = verbose
        self._h = Keccak(capacity=capacity, suffix=self._suffix, verbose=self._verbose)
        self._digest = None
        self.update(m, bitlen=bitlen)

    def export_state(self):
        """Export current state to a dict"""

        if self._digest is None:
            out = self._h.export_state()
            out['digest'] = None
        else:
            out = {}
            digest = self._digest
            out['digest'] = digest
            out['state'] = None
            out['verbose'] = self._verbose
            if self._verbose:
                logging.info('exporting finalized digest:')
                logging.info('  digest:  ' + hexstr(digest))
        return out

    @classmethod
    def import_state(cls, state):
        """Initialize an instance from an exported state"""
        o = cls()
        o._verbose = state['verbose']
        if state['state'] is None:
            o._digest = state['digest']
            o._h = None
            if o._verbose:
                logging.info('importing finalized digest:')
                logging.info('  digest:  ' + hexstr(o._digest))
        else:
            o._h = Keccak.import_state(state)
        return o

    def update(self, m, *, bitlen=None):
        """Update the hash object with the bytes in m. Repeated calls
        are equivalent to a single call with the concatenation of all
        the arguments.
        """
        self._h.absorb(m, bitlen)

    def digest(self):
        """Return the digest of the bytes passed to the update() method
        so far as a bytes object.
        """
        if self._digest is not None:
            return self._digest

        self._digest = self._h.squeez(self.digest_size)
        if self._verbose:
            logging.info('digest: ' + hexstr(self._digest))

        self._h = None

        return self._digest

    def hexdigest(self):
        """Like digest() except the digest is returned as a string
        of double length, containing only hexadecimal digits.
        """
        return binascii.hexlify(self.digest()).decode('ascii')


class sha3_256(sha3_224):
    seclevel = 256


class sha3_384(sha3_224):
    seclevel = 384


class sha3_512(sha3_224):
    seclevel = 512


def shake(seclevel):
    if 128 == seclevel:
        return shake_128
    if 256 == seclevel:
        return shake_256
    raise ValueError(f'seclevel={seclevel}, it must be in [128, 256]')


def sha3(seclevel):
    if 224 == seclevel:
        return sha3_224
    if 256 == seclevel:
        return sha3_256
    if 384 == seclevel:
        return sha3_384
    if 512 == seclevel:
        return sha3_512
    raise ValueError(f'seclevel={seclevel}, it must be in [224, 256, 384, 512]')
