def keyDev(self):
  pick = []
  for i in range(100): #key is the product of 100 primes (with possible repetition)
    pick = pick.append(random.choice(primeList))
  requirement = False
  while requirement = False:
    bitstring = [random.randint(0, 1) for n in range(100)]
    if bitstring.count(1)>=50 and bitstring.count(1)<=70:
      requirement = True
  base = 1
  for i in range(100):
    base *= pick[i] if bitstring[i] == 1
  unused = 1
  for i in range(100):
    unused *= pick[i] if bitstring[i] == 0
  return (base,unused)

def registerDevice(self,name,server):
  factors = sympy.divisors(self.DK)
  newDID = None
  while newDID is None:
    (newDK,unused) = self.keyDev()
    newDID = server.deviceRegistration(self,newDK,unused)
  device2 = Device(name,self.UID,newDID,newDK)
  print(f"New device successfully registered with UID {device2.UID}, DID {device2.DID}, DK {device2.DK}")
  return device2