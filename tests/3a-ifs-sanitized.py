a = source()
if(c>0):
    sink(sanitizer(a))
    a = source()
else:
    sink(a)

sink(a)
