import logging
from test import test


def test_it():
    test.check_against_hashlib(n_seeds=1, max_length=1024 * 4)


if __name__ == '__main__':
    logging.basicConfig(format='%(message)s', level='WARNING')
    test_it()
