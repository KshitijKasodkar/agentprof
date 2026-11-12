from words import top_words

t = "The cat and the hat. The CAT sat; a hat!"
assert top_words(t, 2) == [("the", 3), ("cat", 2)], top_words(t, 2)
assert top_words(t, 3) == [("the", 3), ("cat", 2), ("hat", 2)]
assert top_words("", 3) == []
print("ok")
