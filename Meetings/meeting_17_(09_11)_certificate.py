import random
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

class Server:
    
    def __init__(self, schoolCertDB):
        self.schoolCertDB = schoolCertDB

    def userRegistration(self,User):
        self.schoolCertDB[User.UID] = User.schoolCert

    def deviceRevocation(self, Device, message, cert):
        schoolCert = self.schoolCertDB[Device.DID] #Retrieve device-specific public key
        checkDeviceCert = schoolCert.decrypt(cert)
        checkRequest = checkDeviceCert.decrypt(message)
        if checkRequest == "Retrieve DIDs":
            print("Signature is valid. Revocation process to continue.")
        else:
            print("Signature is invalid. Revocation unauthorised.")

class User: #school
    
    def __init__(self,server:Server):
        self.UID = random.randint(1,100) #Generated as such for the purpose for testing
        self.schoolKey = dsa.generate_private_key(key_size=2048)
        self.schoolCert = self.schoolKey.public_key()
        server.userRegistration(self)

    def generateDeviceCert(self, Device):
        f = self.schoolKey
        return f.encrypt(Device.unsignedCert)

class Device: #teacher

    def __init__(self, server):
        self.DID = random.randint(1,100) #Generated as such for the purpose for testing
        self.deviceKey = dsa.generate_private_key(key_size=2048)
        self.unsignedCert = self.deviceKey.public_key()
        self.deviceCert = school.generateDeviceCert(Device=self)

    def revokeDevice(self,server):
        message = self.deviceKey.encrypt("Retrieve DIDs")
        cert = self.deviceCert
        server.deviceRevocation(self,message,cert)

schoolCertDB = {}
server = Server(schoolCertDB)

choice = int(input("1 to register a new device, 2 to revoke a device, 3 to exit"))
if choice == 1:
        deviceName = input("Device name:")
        school = User(server)
        device = Device(deviceName)
        school.generateDeviceCert()
        print("Device Cert: " + Device.deviceCert)
if choice == 2:
        schoolName = input("School name:")
        deviceName = input("Device name:")
        print(device.revokeDevice())
if choice == 3:
        run = False
else:
        print("Error")
     