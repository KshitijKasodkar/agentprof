from billing import invoice
from cart import cart_total
from pricing import calculate_total

assert invoice([100, 50])["total"] == 177.0
assert cart_total([(10, 2), (5, 1)]) == 25
assert calculate_total([1, 2]) == 3
print("ok")
