def calc(items, tax=0.0):
    return round(sum(items) * (1 + tax), 2)
