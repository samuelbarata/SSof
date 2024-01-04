a = sourceA()
b = sourceB()

sink(a, b)
k = sanitizerC(sanitizerB(sanitizerA(a)))
sink(k)
sink(sanitizerA(k))

# sanitizers through sanitizers
