a=None
a.b=None
a.b.c=None
j = source()
if True:
    # Source -> Sink
    a.b.sink(a.b.c.source())
    # Source
    # Uninitialized variable a.b.c.d [d]
    tmp = a.b.c.d.source()
    sanitized_tmp = a.sanitizer(tmp)
    a.b.sink(tmp, sanitized_tmp)
    a.b.c.k = sanitizer(j)
else:
    a.b.c.k = sanitize(j)

# k is always sanitized
sink(a.b.c.k)
sink(sanitizer(a.b.c.k))


#a = source()
#a.b = source()
#a.b.c = source()
#a.b.c.k = source()

#sink(a)
