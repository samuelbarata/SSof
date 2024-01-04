source = 0
sink(source)

a = source
sink(a)

a = source_1()
source_2 = a
sink(source_2)

# left target only gets taint if the right expression is tainted