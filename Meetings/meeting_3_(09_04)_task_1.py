class client:
    def __init__(self, name, pkey):
        self.name = name
        self.pkey = pkey
        
    def register_server(self, serv):
        self.server = serv
    
    def send_message(self, msg):
        msg = ord(str(msg))
        request = msg**self.pkey
        print (f"{self.name}'s request: {request}")
        return serv.receive_message(request, self)

class server:
    def __init__(self, finalkey, database):
        self.finalkey = finalkey
        self.skeys = {}
        self.database = database

    def register_client(self, client):
        skey = self.finalkey / client.pkey
        self.skeys[client.name] = skey
    
    def receive_message(self, request, client):
        skey = self.skeys[client.name]
        finaloutput = request**skey
        print (f"Final output from {client.name}'s request: {finaloutput}")
        value = self.database.get(finaloutput)
        return value
    
    
def register(client, server):
    client.register_server(server)
    server.register_client(client)

finalkey = float(input("Choose a final key: "))

serv = server(finalkey, database = {
    int(ord(str(2)))**finalkey: "apple",
    int(ord(str(3)))**finalkey: "orange",
    int(ord(str(4)))**finalkey: "banana"
})

valid = False

while not valid:
    Alice_pkey = int(input("Choose an integer for Alice's private key: "))
    Alice_skey = finalkey/Alice_pkey

    Bob_pkey = int(input("Choose an integer for Bob's private key: "))
    Bob_skey = finalkey/Bob_pkey
    
    if Alice_pkey*Alice_skey == Bob_pkey*Bob_skey:
        print("Keys are valid")
        valid = True
        break
    else:
        print("These keys don't work. (For best results, choose integers that the final key is divisible by.)")

Alice = client("Alice", Alice_pkey)
Bob = client("Bob", Bob_pkey)

register(Alice, serv)
register(Bob, serv)

Alice_msg = int(input("Input an integer from 2 to 4 (Alice's message): "))
Alice_returnvalue = Alice.send_message(Alice_msg)
print(f"Item returned: {Alice_returnvalue}")

Bob_msg = int(input("Input the same integer as Alice's message for Bob's message: "))
Bob_returnvalue = Bob.send_message(Bob_msg)
print(f"Item returned: {Bob_returnvalue}")

if Alice_returnvalue == Bob_returnvalue:
    print("Output is valid")
else:
    print("Output is invalid")