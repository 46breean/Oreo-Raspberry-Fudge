
class client:
    def __init__(self, name):
        self.name = name
    
    def convert(self, message):
        msg = ord(str(message))
        return msg
    
    def send_message(self, msg, pkey):
        request = msg**pkey
        return request

class server:
    def receive_message(self, request, skey):
        finaloutput = request**skey
        return finaloutput
    
    def index(self, finaloutput):
        value = database.get(finaloutput)
        return value

serv = server()

Alice = client("Alice")
Bob = client("Bob")

valid = False

while not valid:
    Alice_pkey = int(input("Choose an integer for Alice's private key: "))
    Alice_skey = int(input("Choose an integer for Alice's server key: "))
    Alice_key = Alice_pkey*Alice_skey

    Bob_pkey = int(input("Choose an integer for Bob's private key: "))
    Bob_skey = int(input("Choose an integer for Bob's server key: "))
    Bob_key = Bob_pkey*Bob_skey
    
    if Alice_key == Bob_key:
        print("Keys are valid")
        valid = True
        break
    else:
        print("Choose a distinct pair of integers for each person, such that the product of the integers in each pair is equal")

database = {
    int(ord(str(2)))**Alice_key: "apple",
    int(ord(str(3)))**Alice_key: "orange",
    int(ord(str(4)))**Alice_key: "banana"
}

Alice_msg = Alice.convert(int(input("Input an integer from 2 to 4 (Alice's message): ")))
Alice_req = Alice.send_message(Alice_msg, Alice_pkey)
print(f"Request sent to server by Alice: {Alice_req}")
Alice_output = serv.receive_message(Alice_req, Alice_skey)
print(f"Server output for Alice's request: {Alice_output}")
Alice_returnvalue = serv.index(Alice_output)
print(f"Item returned: {Alice_returnvalue}")

Bob_msg = Bob.convert(int(input("Input the same integer as Alice's message for Bob's message: ")))
Bob_req = Bob.send_message(Bob_msg, Bob_pkey)
print(f"Request sent to server by Bob: {Bob_req}")
Bob_output = serv.receive_message(Bob_req, Bob_skey)
print(f"Server output for Bob's request: {Bob_output}")
Bob_returnvalue = serv.index(Bob_output)
print(f"Item returned: {Bob_returnvalue}")

if serv.index(Alice_output) == serv.index(Bob_output):
    print("Output is valid")
else:
    print("Output is invalid")