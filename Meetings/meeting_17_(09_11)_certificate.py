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
        server.deviceRegistration(self,user)

    @abstractmethod
    def revokeDevice(self,server):
        pass

class AbstractServer(ABC):
    def __init__(self, schoolCertDB, schoolDeviceDB):
        self.schoolCertDB = schoolCertDB
        self.schoolDeviceDB = schoolDeviceDB

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

    def revokeDevice(self,server:AbstractServer,user:AbstractUser,device:AbstractDevice,targetSchool:AbstractUser,targetDevice:AbstractDevice,targetSchoolName:str,targetDeviceName:str):
        message = self.deviceKey.sign(f"Revoke {targetDeviceName} from {targetSchoolName}".encode(),hashes.SHA256())
        server.deviceRevocation(message,self.deviceCertSignature,user,device,targetSchool,targetDevice,targetSchoolName,targetDeviceName)

class Server(AbstractServer):
    def __init__(self,schoolCertDB,schoolDeviceDB):
        super().__init__(schoolCertDB,schoolDeviceDB)

    def deviceRegistration(self,user:AbstractUser,device:AbstractDevice):
        self.schoolCertDB[user.UID] = user.schoolCert
        self.schoolDeviceDB[user.UID] = device.DID

    def deviceRevocation(self, message, certSignature, user:AbstractUser, device:AbstractDevice, targetSchool:AbstractUser, targetDevice:AbstractDevice,targetSchoolName,targetDeviceName):
        schoolCert:dsa.DSAPublicKey = self.schoolCertDB[user.UID] 
        targetSchoolCert:dsa.DSAPublicKey = self.schoolCertDB[targetSchool.UID]
        try: #check valid device certificate
            unsignedCertBytes = device.unsignedCert.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            schoolCert.verify(certSignature,unsignedCertBytes,hashes.SHA256())
        except InvalidSignature:
            print("Device certificate is invalid. Revocation unauthorised.")
            return
        try: #check valid signature
            device.unsignedCert.verify(message,f"Revoke {targetDeviceName} from {targetSchoolName}".encode(),hashes.SHA256())
            print("Valid user, revocation authorised.")
        except InvalidSignature:
            print("Signature is invalid. Revocation unauthorised.")
            return

schoolCertDB = {}
schoolDeviceDB = {}

server = Server(schoolCertDB,schoolDeviceDB)

run = True

while run==True:
    choice = int(input("1 to register a new device, 2 to revoke a device, 3 to exit: "))
    if choice == 1:
        schoolName = input("School name: ")
        deviceName = input("Device name: ")
        school = User(schoolName)
        device = Device(deviceName,school)
        print("Device Cert: ", device.deviceCertSignature)
    elif choice == 2:
        schoolName = input("School name: ")
        deviceName = input("Device name: ")
        targetSchoolName = input("Target School name: ")
        targetDeviceName = input("Target Device name: ")
        user = User(schoolName)
        device = Device(deviceName,user)
        targetUser = User(targetSchoolName)
        targetDevice = Device(targetDeviceName,targetUser)
        print(device.revokeDevice(server,user,device,targetUser,targetDevice,targetSchoolName,targetDeviceName))
    elif choice == 3:
        run = False
    else:
        print("Error")
     
