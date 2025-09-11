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

# server side

def deviceInitialisation(self,unused):
  UID = random.randint(1000000000,9999999999)
  DID = random.randint(1000000000,9999999999)
  baseDSK = random.randint(1,1000000)
  DSK = baseDSK*unused
  self.userDataDB[(UID,DID)] = DSK #databse storing mappings of (UID,DID) to DSK
  return UID, DID

def deviceRegistration(self,Device,newDK,unused):
  try:
    DSK = self.userDataDB[(Device.UID,Device.DID)]
  except KeyError:
    print("You are currenty using a non-registered device, and therefore cannot register other devices.")
    return None
  if DSK == None:
    print("The device you are currently using has been revoked, therefore you are not allowed to execute this function.")
    return None

  existingDIDs = [DID for (UID,DID),DSK in userDataDB.items() if UID == Device.UID]
  existingDSKs = [DSK for (UID,DID),DSK in userDataDB.items() if UID == Device.UID]
  newDSK = baseDSK*unused
  for DSKs in existingDSKs:
    if newDSK == DSKs: #identical DSK has been used for another device
      print("DK generated is invalid, retrying...")
      return None

  while True:
    newDID = random.randint(1000000000,9999999999)
    if newDID not in existingDIDs: #check that identical DID has not been used for another device
      break

  self.userDataDB[(Device.UID,newDID)] = newDSK
  return newDID