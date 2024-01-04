a=source()
for a in range(7):
    sink(source)
    pass
sink(a)
# note: we might not enter the for, we don't know if the iterable object returns 0 iterations in static analysis

a=source()
for a in (1, 2, source()):
    pass
sink(a)

a=source()
for a in 'ola':
    pass
sink(a)

# for assignments
