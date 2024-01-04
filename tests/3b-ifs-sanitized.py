a = source()
b = source()
if(b):
    c = "ABC"
else:
    c = sanitizer(a)
sink(c)

# sanitizer in only one branch; implicit taint through sanitizer (https://mattermost.rnl.tecnico.ulisboa.pt/ssof23/pl/jbfhkhw1g7b6tpsq94ua9tcthh)
