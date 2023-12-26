a = source()
b = source()
if(b):
    c = "ABC"
else:
    c = sanitizer(a)
sink(c)
