import random

P = [9, 11, 23]
G = [2, 3, 5]

p = random.choice(P)
g = random.choice(G)

print("p = " + str(p))
print("g = " + str(g))

a = int(input("Please enter the value of a (Alice's Private Key): "))
b = int(input("Please enter the value of b (Bob's Private Key): "))

a_public = int((g**a)%p)
b_public = int((g**b)%p)

print("Alice's public key is " + str(a_public))
print("Bob's public key is " + str(b_public))

secretkeya = int((b_public**a)%p)
secretkeyb = int((b_public**a)%p)

if secretkeya == secretkeyb:
  print("The shared secret key is " + str(secretkeya))
else:
  print("Error")