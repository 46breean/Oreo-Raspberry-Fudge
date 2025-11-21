import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend
from abc import ABC, abstractmethod
from typing import Protocol
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

#abstract class

class AbstractUser(ABC):
    def __init__(self,name):
        self.schoolName = name
        self.UID = random.randint(1,100) #Generated as such for the purpose for testing
        self.schoolKey = dsa.generate_private_key(key_size=2048)
        self.schoolCert = self.schoolKey.public_key()        

    @abstractmethod
    def generateDeviceCert(self, device):
        pass
        pass

class AbstractDevice(ABC):
    def __init__(self,name,user):
        self.deviceName = name
        self.DID = random.randint(1,100) #Generated as such for the purpose for testing
        self.deviceKey = dsa.generate_private_key(key_size=2048)
        self.unsignedCert = self.deviceKey.public_key()
        self.deviceCertSignature = user.generateDeviceCert(self)

    @abstractmethod
    def revokeDevice(self,server):
        pass

class AbstractServer(ABC):
    def __init__(self, schoolCertDB,schoolDB,deviceDB):
        self.schoolCertDB = schoolCertDB
        self.schoolDB = schoolDB
        self.deviceDB = deviceDB

    @abstractmethod
    def deviceRegistration(self,user,device):
        pass

    @abstractmethod
    def deviceRevocation(self, device, message, cert, user):
        pass

# concrete classes

class User(AbstractUser): 
    def __init__(self,name):
        super().__init__(name)

    def generateDeviceCert(self, device:AbstractDevice):
        unsignedCertBytes = device.unsignedCert.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return self.schoolKey.sign(unsignedCertBytes,hashes.SHA256())

class Device(AbstractDevice): #teacher
    def __init__(self,name,user:AbstractUser):
        super().__init__(name,user)

    def revokeDevice(self,server:AbstractServer,user:AbstractUser,device:AbstractDevice,schoolName:str,targetDeviceName:str):
        message = self.deviceKey.sign(f"Revoke {targetDeviceName} from {schoolName}".encode(),hashes.SHA256())
        server.deviceRevocation(message,self.deviceCertSignature,user,device,targetDeviceName)

class Server(AbstractServer):
    def __init__(self,schoolCertDB,schoolDB,deviceDB):
        super().__init__(schoolCertDB,schoolDB,deviceDB)

    def deviceRegistration(self,schoolName:str,deviceName:str):
        registeredSchools = schoolDB.keys()
        if schoolName not in registeredSchools:
            user = User(schoolName)
            self.schoolDB[schoolName] = user
            device = Device(deviceName,user)
            self.schoolCertDB[user.UID] = user.schoolCert
        else:
            user = self.schoolDB[schoolName]
            device = Device(deviceName,user)
        deviceDB[(schoolName,deviceName)] = device

    def deviceRevocation(self, message, certSignature, user:AbstractUser, device:AbstractDevice, targetDeviceName:str):
        try: #check valid device certificate
            schoolCert=schoolCertDB[user.UID]
            unsignedCertBytes = device.unsignedCert.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            schoolCert.verify(certSignature,unsignedCertBytes,hashes.SHA256())
        except InvalidSignature:
            print("Device certificate is invalid. Revocation unauthorised.")
            return
        try: #check valid signature
            device.unsignedCert.verify(message,f"Revoke {targetDeviceName} from {user.schoolName}".encode(),hashes.SHA256())
            print("Valid user, revocation authorised.")
        except InvalidSignature:
            print("Signature is invalid. Revocation unauthorised.")
            return

schoolCertDB = {} #stores the public keys for each school
schoolDB = {} #maps all schools to their schoolName
deviceDB = {} #maps all devices to their (schoolName, deviceName)

server = Server(schoolCertDB,schoolDB,deviceDB)

run = True

while run==True:
    choice = input("1 to register a new device, 2 to revoke a device, 3 to exit: ")
    if choice == "1":
        schoolName = input("School name: ")
        deviceName = input("Device name: ")
        server.deviceRegistration(schoolName, deviceName)
        device = deviceDB[(schoolName, deviceName)]
        print("Device Cert: ", device.deviceCertSignature.hex())
        continue
    elif choice == "2":
        schoolName = input("School name: ")
        deviceName = input("Device name: ")
        try:
            user = schoolDB[schoolName]
        except KeyError:
            print("This school does not have any registered devices.")
            continue
        try:
            device = deviceDB[(schoolName,deviceName)]
        except KeyError:
            print("This device is not registered under the school.")
            continue
        targetDeviceName = input("Target Device name: ")
        try:
            targetDevice = deviceDB[(schoolName,targetDeviceName)]
        except KeyError:
            print("The target device is not under the same school as this device. Revocation unauthorised.")
            continue
        message = f"Revoke {targetDeviceName} from {schoolName}".encode(),hashes.SHA256()
        print(device.revokeDevice(server,user,device,schoolName,targetDeviceName))
        continue
    elif choice == "3":
        run = False
        continue
    else:
        print("Invalid input, please try again.")
        continue