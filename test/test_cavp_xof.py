import logging
from test import test


def test_it():
    test.check_xof_against_nist_cavp()


if __name__ == '__main__':
    logging.basicConfig(format='%(message)s', level='WARNING')
    test_it()
