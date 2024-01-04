a=source()
e=source()
if(e==0):
    e=a
else:
    e=0
sink(e)

# although the variable is rewritten on both branches, there is an implicit flow
