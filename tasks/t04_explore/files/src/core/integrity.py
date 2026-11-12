MODULUS = 65521


def compute_checksum(data):
    a, b = 1, 0
    for ch in data:
        a = (a + ch) % MODULUS
        b = (b + a) % MODULUS
    return (b << 16) | a
