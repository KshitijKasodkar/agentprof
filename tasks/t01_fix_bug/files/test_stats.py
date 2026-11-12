from stats import mean, median, variance

assert mean([1, 2, 3, 4]) == 2.5
assert median([5, 1, 3]) == 3
assert median([4, 1, 3, 2]) == 2.5, median([4, 1, 3, 2])
assert variance([2, 4, 4, 4, 5, 5, 7, 9]) == 4
print("all tests passed")
