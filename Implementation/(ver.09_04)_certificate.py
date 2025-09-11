from primePy import primes
import random
import sys
import hashlib
import math
import sympy

primeList = primes.upto(1000) #104729 is the 10 000th prime number

def random_coprime(p_minus_1): #randomly generate a number coprime to an input integer
    while True:
        r = random.randint(2, p_minus_1)
        if math.gcd(r, p_minus_1) == 1:
            return r

class Device:

    #attributes

    def __init__(self,name,UID=None,DID=None,DK=None):
        self.name = name
        self.UID = UID
        self.DID = DID
        self.DK = DK
        self.p = server.p

        nameDB[self.name] = self

    #key derivation algorithm

    def keyDev(self):
        base = 1
        for i in range(100): #key is the product of 100 primes (with possible repetition)
            pick = random.choice(primeList)
            base *= pick
        return base

    #initialisation function

    def initialiseDevice(self,server):
        self.DK = self.keyDev()
        self.UID, self.DID, cert = server.deviceInitialisation()
        print(f"User and device successfully initialised with UID {self.UID}, DID {self.DID}, DK {self.DK}\nYour school certificate is {cert}")
    
    #registration function

    def registerDevice(self,name,server):
        factors = sympy.divisors(self.DK)

        newDID = None
        while newDID is None:
            n = random.choice(factors)
            newDID,cert = server.deviceRegistration(self,n)

        newDK = self.DK//n #newDK is a random factor of original DK
        
        device2 = Device(name,self.UID,newDID,newDK)
        print(f"New device successfully registered with UID {device2.UID}, DID {device2.DID}, DK {device2.DK}\nYour school certificate is {cert}")
        return device2
    
    #revocation function

    def revokeDevice(self,server):
        existingDIDs = server.deviceRevocation(self,"Retrieve DIDs")
        if existingDIDs == None: #no devices have been registered
            return
        valid = False
        while not valid:
            print(f"DIDs of registered, not yet revoked devices: {existingDIDs}")
            while True:
                try:
                    DIDtoRevoke = int(input("Please type the DID of the device that you would like to revoke: ")) #user inputs DID of compromised device
                except ValueError:
                    print("Invalid input, please enter an integer. ")
                try:
                    cert = int(input("Please input your school certificate for verification."))
                    break
                except ValueError:
                    print("Invalid input, please enter an integer. ")
            valid = server.deviceRevocation(self,"Revoke selected DID",cert,DIDtoRevoke)
        
        print(f"Device with DID {DIDtoRevoke} has been successfully revoked.")

class Server:

    #attributes

    def __init__(self,userDataDB,userCertDB,indexDataDB,encDB,p=29996224275833):
        self.userDataDB = userDataDB
        self.userCertDB = userCertDB
        self.indexDataDB = indexDataDB
        self.encDB = encDB
        self.p = p
    
    #function selection

    def retrieveDevice(self):
        while True:
                deviceName = input("What is the name of the device that you are using? ")
                device = nameDB.get(deviceName)
                if device:
                    return device
                else:
                    print("Device not found. Please try again.")

    def fnSelection(self):
        function = int(input("Select the function you want to execute.\n1: Initialisation\n2: Registration\n3: Revocation\n4: Evaluation\n5: View userDataDB\n6: Quit\n"))
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
            for (uid, did), dsk in server.userDataDB.items():
                print(f"Server database entry → (UID: {uid}, DID: {did}), DSK: {dsk}")
        elif function == 6:
            print("Goodbye!")
            sys.exit()
        else:
            print("Select one of the functions listed.")
        server.fnSelection()

    #initialisation function

    def deviceInitialisation(self):
        UID = random.randint(1000000000,9999999999)
        DID = random.randint(1000000000,9999999999)
        DSK = random.randint(1,1000000)
        cert = random.randint(1000000000,9999999999)

        self.userDataDB[(UID,DID)] = DSK #database storing mappings of (UID,DID) to DSK
        self.userCertDB[UID] = cert
        return UID, DID, cert

    #registration function

    def deviceRegistration(self,Device,n):
        while True:
            try:
                DSK = self.userDataDB[(Device.UID,Device.DID)]
                break
            except KeyError:
                print("You are currenty using a non-registered device, and therefore cannot register other devices.")
                return None
        if DSK == None:
            print("The device you are currently using has been revoked, therefore you are not allowed to execute this function.")
            return None
        
        existingDIDs = [DID for (UID,DID),DSK in userDataDB.items() if UID == Device.UID]
        existingDSKs = [DSK for (UID,DID),DSK in userDataDB.items() if UID == Device.UID]
        newDSK = DSK*n #newDSK is a multiple of original DSK
        for DSKs in existingDSKs:
            if newDSK == DSKs: #identical DSK has been used for another device
                print("n generated is invalid, retrying...")
                return None

        while True:
            newDID = random.randint(1000000000,9999999999)
            if newDID not in existingDIDs: #check that identical DID has not been used for another device
                break
    
        self.userDataDB[(Device.UID,newDID)] = newDSK
        cert = self.userCertDB[Device.UID]

        return newDID,cert
    
    #revocation function

    def deviceRevocation(self,Device,message,DIDtoRevoke=None,cert=None):
        existingDIDs = [DID for (UID,DID),DSK in userDataDB.items() if UID == Device.UID and DSK != None] #check that device exists and is not already revoked

        if message == "Retrieve DIDs":
            try:
                DSK = self.userDataDB[(Device.UID,Device.DID)]
            except KeyError:
                print("You are currenty using a non-registered device, and therefore cannot revoke other devices.")
                return None
            if self.userDataDB[(Device.UID,Device.DID)] == None:
                print("The device you are currently using has been revoked, and therefore you are not allowed to execute this function.")
                return None
            else:
                return existingDIDs
        if message == "Revoke selected DID":
            if cert != self.userCertDB[Device.UID]:
                print("You have provided an invalid certificate.")
                return False
            if DIDtoRevoke not in existingDIDs:
                print("Device has not yet been registered.")
                return False
            elif self.userDataDB[(Device.UID,DIDtoRevoke)] == None:
                print("Device has already been revoked.")
                return False
            else:
                self.userDataDB[(Device.UID,DIDtoRevoke)] = None
                return True

nameDB, userDataDB, userCertDB, indexDataDB, encDB = {}, {}, {}, {}, {}
server = Server(userDataDB,userCertDB,indexDataDB,encDB)

server.fnSelection()