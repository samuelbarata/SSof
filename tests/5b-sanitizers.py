a=None
a.b = None
a.b.c = source()
if True:
    tmp = sanitizer(a.b.c)
else:
    tmp = sanitizer(a.b.c)
sink(tmp)

# both branches are sanitized
