from pricing import calc


def invoice(items):
    return {"total": calc(items, 0.18)}
