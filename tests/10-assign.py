a=b=c=source()
sink(a)
sink(b)
sink(c)

a,b = (True, source())
sink(a)
sink(b)
