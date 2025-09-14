from primePy import primes
import random
import math
from collections import Counter
import matplotlib.pyplot as plt

primeList = primes.upto(1000)

x = 3 #number of factors
g = 100 #generator
m = random.randint(100,999)

output = []

for i in range(0,1000):
  N = 1
  for j in range(0,x):
    N *= random.choice(primeList)
  print(N)
  output.append((m**N)%g)

frequency = Counter(output)

categories = list(frequency.keys())
frequencies = list(frequency.values())

print(frequency)

plt.bar(categories, frequencies, color='skyblue')
plt.show()