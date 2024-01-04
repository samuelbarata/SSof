for a in range(source()):
    sink(source)
    source = source()

# vulnerability only on second iteration
