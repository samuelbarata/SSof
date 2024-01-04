a=source()
b=source()
for a in range(5):
    sink(b)
    for i in range(3):
        sink(i)
        sink(sanitizer(a))
        sink(sanitizer(source()))
        sink(b)
    b = a  # vulnerabilities only on firt iteration
sink(a)
# note: we might not enter the for, we don't know if the iterable object returns 0 iterations in static analysis
sink(sanitizer(a))
sink(b)

# nested for loops with sanitizers
