import hashlib
import random
from fastapi import FastAPI

app = FastAPI()

class client:
    def __init__(self, name):
        self.name = name

    def register(self, referral_client=None):
        self.server = serv
        self.server.register_client(self, referral_client)

    def register_server(self, serv):
        self.server = serv
        self.pkey = random.randint(1, 3)

    def register_server_withreferral(self, serv, client):
        self.server = serv
        self.pkey = random.randint(1, 3)
        factor = self.pkey/client.pkey
        return factor        
    
    def blinding_1(self, msg):
        msg = hash(msg)
        self.r_1 = random.randint(1, 3)
        a = (msg**self.pkey)**self.r_1
        c = self.server.blinding_2(a, self)**(1/self.r_1)
        return c
    
    def register_object(self, msg, object):
        c = self.blinding_1(msg)      
        self.server.register_object(c, object)

    def get_object(self, msg):
        c = self.blinding_1(msg)
        return self.server.get_object(c)

class server:
    def __init__(self):
        self.skeys = {}
        self.database ={}

    def register_client(self, client, referral_client=None):
        if bool(self.skeys) == False:
            skey = random.randint(1, 3)
            client.register_server(self)
        else:
            factor = client.register_server_withreferral(self, referral_client)
            skey = self.skeys[referral_client.name]/factor
        self.skeys[client.name] = skey

    def register_object(self, c, object): 
        message = int(c**(1/self.r_2))
        print(f"Alice's message {message}")
        d = hash(message)
        print(f"Alice d {d}")
        self.database[d] = object
    
    def blinding_2(self, a, client):
        self.r_2 = random.randint(1, 3)
        skey = self.skeys[client.name]
        b = (a**skey)**self.r_2
        return b
    
    def get_object (self, c):
        message = int(c**(1/self.r_2))
        print(f"Bob's message {message}")
        d = hash(message)
        print(f"Bob's d {d}")
        return self.database[d]
    
def hash(message):
    m = hashlib.md5()
    message = str(message)
    m.update(message.encode("utf-8"))
    return(int(m.hexdigest(), 16)%10000)

serv = server()

Alice = client("Alice")
Bob = client("Bob")

Alice.register()
Bob.register(Alice)

msg = input("Input an integer from 2 to 4 (Alice's message): ")
object = input("(Alice) Register an object: ")
Alice.register_object(msg, object)
Alice_registeredobject = object

msg = input("Input the same integer as Alice's message for Bob's message: ")
Bob_returnvalue = Bob.get_object(msg)
print(f"The object retrieved is {Bob_returnvalue}.")

if Alice_registeredobject == Bob_returnvalue:
    print("Output is valid")
else:
    print("Output is invalid")