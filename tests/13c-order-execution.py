tainted = ""
untainted = ""
f(tainted := source(), sink1(tainted))
f(sink2(untainted), untainted := source())

tainted = ""
untainted = ""
(tainted := source()) + sink3(tainted)
sink4(untainted) + (untainted := source())

# assigns inside functions; order execution

# inspired by 2022/2023 T46-05
