a = source()
if(c>0):
    sink(sanitizer(a))
    a = source()
else:
    sink(a)

sink(a)

# taints in one branch don't interfere with the other one
