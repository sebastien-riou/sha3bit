import logging
from test import test


def test_it():
    test.check_api_xof_absorb()


if __name__ == '__main__':
    logging.basicConfig(format='%(message)s', level='WARNING')
    test_it()
