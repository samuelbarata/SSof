a = None
b = None
c = source()

# The state is always changing >:)
for t in a:
    a = b
    b = c
    c = t

sink(a)

# Inspired by T04-05/perpetual-swap.py
