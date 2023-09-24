import argparse
import logging

from pysatl import Utils

import sha3bit

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='sha3bit.cli')
    levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    parser.add_argument('--log-level', default='WARNING', choices=levels)
    parser.add_argument('--bit-length', help='Bit length of message', default=None, type=int)
    alg_group = parser.add_mutually_exclusive_group(required=True)
    alg_group.add_argument('--sha3-224', help='Use SHA3-224 algorythm', action='store_true')
    alg_group.add_argument('--sha3-256', help='Use SHA3-256 algorythm', action='store_true')
    alg_group.add_argument('--sha3-384', help='Use SHA3-384 algorythm', action='store_true')
    alg_group.add_argument('--sha3-512', help='Use SHA3-512 algorythm', action='store_true')
    alg_group.add_argument('--shake-128', help='Use SHAKE-128 algorythm', action='store_true')
    alg_group.add_argument('--shake-256', help='Use SHAKE-256 algorythm', action='store_true')
    parser.add_argument('--digest-size', help='Output size in bytes', default=None, type=int)
    parser.add_argument('message', nargs=1, help='Message to hash', type=str)
    args = parser.parse_args()

    logging.basicConfig(format='%(message)s', level=args.log_level)

    msg = Utils.ba(args.message[0])

    cls = None
    xof = False
    if args.sha3_224:
        cls = sha3bit.sha3(224)
    if args.sha3_256:
        cls = sha3bit.sha3(256)
    if args.sha3_384:
        cls = sha3bit.sha3(384)
    if args.sha3_512:
        cls = sha3bit.sha3(512)
    if cls is None:
        xof = True
    if args.shake_128:
        cls = sha3bit.shake(128)
    if args.shake_256:
        cls = sha3bit.shake(256)

    verbose = args.log_level in ['DEBUG', 'INFO']
    impl = cls(msg, bitlen=args.bit_length, verbose=verbose)

    if args.digest_size is None:
        output_size = impl.digest_size
    else:
        output_size = args.digest_size

    if xof:
        digest = impl.digest(output_size)
    else:
        if output_size != impl.digest_size:
            raise ValueError(
                'digest-length is %d but SHA3-%d support only %d' % (output_size, impl.seclevel, impl.digest_size)
            )
        digest = impl.digest()

    if not verbose:
        print(Utils.hexstr(digest))
