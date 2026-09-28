def ba(hexstr):
    """Convert a hex string to a bytearray.

    Any non alphanumeric character is a separator, '0x' prefixes are ignored
    and each hex group with an odd number of digits is left padded with a '0'.
    Non-string arguments (bytes, list of int...) are passed to bytearray().
    Raises ValueError if the conversion fails.
    """
    if not isinstance(hexstr, str):
        try:
            return bytearray(hexstr)
        except TypeError as e:
            raise ValueError() from e
    out = bytearray()
    tokens = ''.join([c if c.isalnum() else ' ' for c in hexstr.lower()]).split()
    for token in tokens:
        if token.startswith('0x'):
            token = token[2:]
        if len(token) % 2:
            token = '0' + token
        out += bytearray.fromhex(token)
    return out


def hexstr(data):
    """Return an upper case hex string of data, bytes separated by a space"""
    return ' '.join([f'{b:02X}' for b in data])
