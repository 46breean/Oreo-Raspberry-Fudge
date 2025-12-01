p = int(input("prime: "))

def order(a, p):
    n = 1
    while True:
        if pow(a, n, p) == 1:
            return n
        n += 1

for x in range(1, p):
    ox  = order(x, p)
    opx = order(p - x, p)
    if ox != opx:
        print(x, ox, opx)