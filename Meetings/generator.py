from primePy import primes
import random
import math
from collections import Counter
import matplotlib.pyplot as plt

primeList = primes.upto(1000)

x = 100 #number of factors
g = 7931 #generator

N=[]

for i in range(100):
    N.append(random.choice(primeList))

output = []

#generate a1...a1000

for i in range(0,1000):
    fac=1
    bitcount = random.randint(50, 70)      
    zeros = len(N) - bitcount
    bitstring = [1]*bitcount + [0]*zeros
    random.shuffle(bitstring)
    for j in range(100):
        if bitstring[j] == 1:
            fac = (fac*N[j])%g
    output.append(fac)

print("Possible keys generated")

#generate possible values of lamdax

lamdax=[1,2,5,10,13,26,61,65,122,130,305,610,793,1586,3965,7930]

print("Possible lamdax generated")

probability={}

for i in range(len(lamdax)):
    remainder=[]
    for k in range(len(output)):
        remainder.append(output[k]%lamdax[i])
    uniqueRemainders = list(set(remainder))
    repetitionCount=[]
    for k in range(len(uniqueRemainders)):
        repetitionCount.append(remainder.count(uniqueRemainders[k]))
    probabilityCalc=0
    for k in range(len(repetitionCount)):
        probabilityCalc+=((repetitionCount[k])/len(output))*((repetitionCount[k]-1)/len(output))
    probability[lamdax[i]]=probabilityCalc

print("Probabilities calculated")

print(probability)
    

lamdax = list(probability.keys())
clashProb = list(probability.values())

plt.bar(lamdax, clashProb, color='skyblue')
plt.show()
