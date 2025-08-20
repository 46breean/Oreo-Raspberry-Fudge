from primePy import primes
import random
import sys
import hashlib
import math

primeGen = 997
primeList = primes.upto(1000)

class Device:

  #attributes

  def __init__(self,name,UID=None,DID=None,DK=None):
    self.name = name
    self.UID = UID
    self.DID = DID
    self.DK = DK
    self.p = server.p

    DBname[self.name] = self

  #key derivation algorithm

  def keyDev(self):
    base = 1
    for i in range(10):
      pick = random.choice(primeList)
      base *= pick
    return base

  #initialisation function

  def initialiseDevice(self,server):
    self.DK = self.keyDev()
    self.UID, self.DID = server.deviceInitialisation()
    print(f"User and device successfully initialised with UID {self.UID}, DID {self.DID}, DK {self.DK}")
  
  #registration function

  def registerDevice(self,name,server):
    factors = primes.factors(self.DK)

    valid = False
    while not valid:
      n = random.choice(factors)
      valid, newDID = server.deviceRegistration(self,n)

    newDK = self.DK//n
    
    device2 = Device(name,self.UID,newDID,newDK)
    print(f"New device successfully registered with UID {device2.UID}, DID {device2.DID}, DK {device2.DK}")
    return device2
  
  #revocation function

  def revokeDevice(self,server):
    existingDIDs = server.deviceRevocation(self,"Retrieve DIDs")
    if existingDIDs == None:
      return
    valid = False
    while not valid:
      print(f"DIDs of registered devices: {existingDIDs}")
      DIDtoRevoke = int(input("Please type the DID of the device that you would like to revoke: "))
      valid = server.deviceRevocation(self,"Revoke selected DID",DIDtoRevoke)
    
    print(f"Device with DID {DIDtoRevoke} has been successfully revoked.")

  #evaluation functions

  def hash(msg):
    m = hashlib.sha256()
    msg = str(msg)
    m.update(msg.encode())
    return(int(m.hexdigest(), 16))

  def evaluate(self,server):
    def random_coprime(p_minus_1):
      while True:
        r = random.randint(2, p_minus_1)
        if math.gcd(r, p_minus_1) == 1:
          return r
    r1 = random_coprime(self.p-1)
    x = int(input("Enter a number to evaluate:"))
    Hx = hash(x)
    blinded = pow(Hx, self.DK * r1, self.p)
    blinded2 = server.servblinding(self.UID, self.DID, blinded)
    unblinded1 = pow(blinded2, pow(r1, -1, self.p-1), self.p)
    server.evaluate(unblinded1)



class Server:

  #attributes

  def __init__(self,DB1,DB2,DB3,p=7919):
    self.DB1 = DB1
    self.DB2 = DB2
    self.DB3 = DB3
    self.p = p
  
  #function selection

  def retrieveDevice(self):
    while True:
        deviceName = input("What is the name of the device that you are using? ")
        device = DBname.get(deviceName)
        if device:
          return device
        else:
          print("Device not found. Please try again.")

  def fnSelection(self):
    function = int(input("Select the function you want to execute.\n1: Initialisation\n2: Registration\n3: Revocation\n4: Evaluation\n5: View DB1\n6: Quit\n"))
    if function == 1:
      deviceName = input("What would you like to name your device? ")
      deviceName = Device(deviceName)
      deviceName.initialiseDevice(self)
    elif function == 2:
      device = server.retrieveDevice()
      newDeviceName = input("What would you like to name your new device? ")
      device.registerDevice(newDeviceName,self)
    elif function == 3:
      device = server.retrieveDevice()
      device.revokeDevice(self)
    elif function == 4:
      device = server.retrieveDevice()
      device.evaluate(self)
    elif function == 5:
      for (uid, did), dsk in server.DB1.items():
        print(f"Server database entry → UID: {uid}, DID: {did}, DSK: {dsk}")
    elif function == 6:
      print("Goodbye!")
      sys.exit()
    server.fnSelection()

  #initialisation function

  def deviceInitialisation(self):
    UID = random.randint(1000000000,9999999999)
    DID = random.randint(1000000000,9999999999)
    DSK = random.randint(1,1000000)

    self.DB1[(UID,DID)] = DSK

    return UID, DID

  #registration function

  def deviceRegistration(self,Device,n):
    DSK = self.DB1[(Device.UID,Device.DID)]
    if DSK == None:
      print("UID and/or DID does not exist in database.")
      return False, None
    
    existingDIDs = [DID for (UID,DID),DSK in DB1.items() if UID == Device.UID]
    existingDSKs = [DSK for (UID,DID),DSK in DB1.items() if UID == Device.UID]
    newDSK = DSK*n
    for DSKs in existingDSKs:
      if newDSK == DSKs:
        print("n generated is invalid, retrying...")
        return False, None

    while True:
      newDID = random.randint(1000000000,9999999999)
      if newDID not in existingDIDs:
          break
  
    self.DB1[(Device.UID,newDID)] = newDSK
    return True, newDID
  
  #revocation function

  def deviceRevocation(self,Device,message,DIDtoRevoke=None):
    existingDIDs = [DID for (UID,DID),DSK in DB1.items() if UID == Device.UID]

    if message == "Retrieve DIDs":
      if self.DB1[(Device.UID,Device.DID)] == None:
        print("You are currently using a non-registered device and are therefore not allowed to execute this function.")
        return None
      else:
        return existingDIDs
    if message == "Revoke selected DID":
      if DIDtoRevoke not in existingDIDs:
        print("Device has not yet been registered.")
        return False
      elif self.DB1[(Device.UID,DIDtoRevoke)] == None:
        print("Device has already been revoked.")
        return False
      else:
        self.DB1[(Device.UID,DIDtoRevoke)] = None
        return True
  def evaluate(self,Device,message):
    pass

  #evaluation functions

  def servblinding(self, UID, DID, blinded):
    def random_coprime(p_minus_1):
      while True:
        r = random.randint(2, p_minus_1)
        if math.gcd(r, p_minus_1) == 1:
          return r
    self.r2 = random_coprime(self.p-1)
    DSK = self.DB1[(UID, DID)]
    blinded2 = pow(blinded, DSK * self.r2, self.p)
    return blinded2

  def evaluate(self,unblinded1):
    final_eval = pow(unblinded1, pow(self.r2, -1, self.p-1), self.p)
    print (final_eval)

DBname, DB1, DB2, DB3 = {}, {}, {}, {}
server = Server(DB1,DB2,DB3)

server.fnSelection()