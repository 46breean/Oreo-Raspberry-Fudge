import math

#parameters
p = 29996224275833
print("Prime: " + str(p))
target = p-1
numberOfTrials = 12
confidence = 0.8

#required |X|
numberOfx = math.ceil((1-(1-confidence)**(1/numberOfTrials))*(p-1))
print("Sample space size: " + str(numberOfx))

#prime factorisation
def factors(n):
    result = []
    i = 1
    while i * i <= n:
        if n % i == 0:
            result.append(i)
            if i != n // i:      
                result.append(n // i)
        i += 1
    return sorted(result)

factor = factors(target)

lamdaX = {}

for i in factor:
  lamdaX[i]=int(target/i)

#max lamdaX
sum = 0
currentFactor = 1
i = 0
collProb = 0

while sum<numberOfx:
  currentFactor = factor[i]
  sum += factor[i]
  i+=1
  collProb += (factor[i]*(factor[i]-1))/(p-1)**2

maxlamdax = (p-1)/factor[i]
print("Maximum lamda x: " + str(maxlamdax))

#calculate collision probability
print("Collsion probability: " + str(collProb))
