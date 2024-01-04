a=source()
for a in range(7):
    sink(source)
    pass
sink(a)

a=source()
for a in (1, 2, source()):
    pass
sink(a)

a=source()
for a in 'ola':
    pass
sink(a)

