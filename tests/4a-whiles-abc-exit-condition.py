a = source()
b = None
c = None
d = None
e = None
f = None
g = None
h = None
i = None
j = None
k = None
l = None
m = None
n = None
o = None
p = None
q = None
r = None
s = None
t = None
u = None
v = None
w = None
x = None
y = None
z = None
while True:
    sink(z)
    z = y
    y = w
    w = x
    x = v
    v = u
    u = t
    t = s
    s = r
    r = q
    q = p
    p = o
    o = n
    n = m
    m = l
    l = k
    k = j
    j = i
    i = h
    h = g
    g = f
    f = e
    e = d
    d = c
    c = b
    b = a
sink(o)

# wait for taints to stop propagate in whiles before breaking the execution
