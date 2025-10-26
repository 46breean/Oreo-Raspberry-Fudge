import random
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

class User: #school
    
    def __init__(self,server):
        self.UID = random.randint(1,100) #Generated as such for the purpose for testing
        self.schoolKey = dsa.generate_private_key(key_size=2048)
        self.schoolCert = self.schoolKey.public_key()
        server.schoolCertDB[self.DID] = self.schoolCert

    def generateDeviceCert(self, Device):
        f = self.schoolKey
        return f.encrypt(Device.unsignedCert)

class Device: #teacher

    def __init__(self, server):
        self.DID = random.randint(1,100) #Generated as such for the purpose for testing
        self.deviceKey = dsa.generate_private_key(key_size=2048)
        self.unsignedCert = self.deviceKey.public_key()
        self.deviceCert = User.generateDeviceCert(self.unsignedCert)

    def revokeDevice(self,server):
        message = self.deviceKey.encrypt("Retrieve DIDs")
        cert = self.deviceCert
        server.deviceRevocation(self,message,cert)

class Server:
    
    def __init__(self, schoolCertDB):
        self.schoolCertDB = schoolCertDB

    def deviceRevocation(self, Device, message, cert):
        schoolCert = self.schoolCertDB[Device.DID] #Retrieve device-specific public key
        checkDeviceCert = schoolCert.decrypt(cert)
        checkRequest = checkDeviceCert.decrypt(message)
        if checkRequest == "Retrieve DIDs":
            print("Signature is valid. Revocation process to continue.")
        else:
            print("Signature is invalid. Revocation unauthorised.")

schoolCertDB = {}
server = Server(schoolCertDB)