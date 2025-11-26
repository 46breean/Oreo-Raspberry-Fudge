p = int(input("prime: "))

orders = []
for i in range(1, p):
    n = 1
    while True:
        if pow(i, n, p) == 1:
            orders.append(n)
            break
        n += 1

print(orders)

print(orders[::-1])
