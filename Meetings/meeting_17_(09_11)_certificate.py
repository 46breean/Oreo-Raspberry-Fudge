import random
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes

class Device: #Working device

    def __init__(self, server):
        self.DID = random.randint(1,100) #Generated as such for the purpose for testing
        self.privateKey = dsa.generate_private_key(key_size=2048)
        self.publicKey = self.privateKey.public_key()
        server.publicKeyDB[self.DID] = self.publicKey #Store as DID : publicKey pairs in server dictionary

    def revokeDevice(self,server):
        message = ("Retrieve DIDs").encode()
        signature = self.privateKey.sign(message, hashes.SHA256()) #Sign message
        server.deviceRevocation(self, message, signature)

class Bad_Device: #Non-working device

    def __init__(self, server):
        self.DID = random.randint(1,100) #Generated as such for the purpose for testing
        self.privateKey = dsa.generate_private_key(key_size=2048)
        self.publicKey = self.privateKey.public_key()
        server.publicKeyDB[self.DID] = self.publicKey #Store as DID : publicKey pairs in server dictionary

    def revokeDevice(self,server):
        message = ("Retrieve DIDs").encode() #Encode in bytes
        badSignature = ("Bad Signature").encode() #Encodes a faulty signature in bytes
        server.deviceRevocation(self, message, badSignature)

class Server:
    
    def __init__(self, publicKeyDB):
        self.publicKeyDB = publicKeyDB

    def deviceRevocation(self, Device, message, signature):
        publicKey = self.publicKeyDB[Device.DID] #Retrieve device-specific public key
        try:
            publicKey.verify(signature, message, hashes.SHA256())
            print("Signature is valid. Revocation process to continue.")
        except Exception:
            print("Signature is invalid. Revocation unauthorised.")

publicKeyDB = {}
server = Server(publicKeyDB)
goodDevice = Device(server)
badDevice = Bad_Device(server)
goodDevice.revokeDevice(server)
badDevice.revokeDevice(server)