from pricing import calc


def cart_total(cart):
    return calc([p * q for p, q in cart])
