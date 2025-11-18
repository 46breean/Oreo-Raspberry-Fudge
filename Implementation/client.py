import requests, random, math, hashlib, socket, sys, threading, time, tempfile, os, json, ast
from primePy import primes

SERVER = "http://172.22.22.27:8000"

def hash_int(x: int) -> int:
    m = hashlib.sha256()
    m.update(str(x).encode())
    return int(m.hexdigest(), 16)

def random_coprime(p_minus_1: int) -> int:
    while True:
        r = random.randint(2, p_minus_1)
        if math.gcd(r, p_minus_1) == 1:
            return r

def keyDev():
    keyproduct = [random.choice(primeList) for _ in range (100)]
    bitstring = []

    requirement = False
    while requirement == False:
        bitstring = [random.randint(0, 1) for _ in range(100)]
        if bitstring.count(1)>=50 and bitstring.count(1)<=70:
            requirement = True
    base = 1
    unused = 1

    for i in range(100):
        if bitstring[i] == 1:
            base *= keyproduct[i]
        else:
            unused *= keyproduct[i]

    return base, unused, keyproduct

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def init_reg():
    while True:
        print("\nSign Up: Register new device")

        uid = input("Enter your UID: ")
        admin_did = input("Enter your admin DID: ")

        try:
            loc = requests.get(
                f"{SERVER}/device_location",
                params={"uid": uid, "did": admin_did}
            )
            loc.raise_for_status()
            referral_info = loc.json()
            referral_ip = referral_info["ip"]
            referral_port = referral_info["port"]
        except requests.exceptions.HTTPError as e:
            print("Could not find referral device:", e.response.json()["detail"])
            sys.exit(1)

        # connect to admin device
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"Connecting to referral device at {referral_ip}:{referral_port}...")
            s.connect((referral_ip, referral_port))
            s.sendall(b"Registration Request")
            admin_reply = s.recv(4096).decode()
            if admin_reply == b"REJECTED":
                print("Registration Request Rejected")
                sys.exit()
            else:
                data = json.loads(admin_reply)
                did, dk, unused, keyproduct = (
                    data["DID"],
                    data["DK"],
                    data["unused"],
                    data["keyproduct"]
                )
                did, dk, unused, keyproduct = int(did), int(dk), int(unused), list(keyproduct)
                print(f"[Device {DID}] Device registration completed")

        return uid, did, dk

def fn_selection(UID, DID, DK):

    while True:
        print("\nDevice Menu:")
        print("1. Revoke device")
        print("2. Evaluate and Query")
        print("3. Edit Database")
        print("4. Exit")
        choice = int(input("Select function: "))

        if choice == 1:
            try:
                revoke_list = requests.get(
                    f"{SERVER}/revoke_list",
                    params = {"uid": UID, "did": DID}
                )
                revoke_list.raise_for_status()
            except requests.exceptions.HTTPError as e:
                print ("Current device not found")
                sys.exit(1)
            
            print(f"DIDs of registered, not yet revoked devices: {revoke_list.json()}")

            revoke_did = int(input("Select DID to revoke:"))

            revoke = requests.post(
                f"{SERVER}/revoke",
                json={"uid": UID, "did": DID, "revoke_did": revoke_did}
            ).json()
            print(revoke)
        
        elif choice == 2:
            index = int(input("Enter a student data query: "))
            hashed_index = hash_int(index) % p
            r1 = random_coprime(p - 1)

            blinded = pow(hashed_index, DK * r1, p)

            try:
                resp1 = requests.post(
                    f"{SERVER}/eval/step1",
                    json={"uid": UID, "did": DID, "blinded": blinded}
                )
                resp1.raise_for_status()
            except requests.exceptions.HTTPError as e:
                print("Step 1 failed:", e.response.json()["detail"])
                input("Press Enter to continue...")
                return
            try:
                blinded2 = resp1.json()["blinded2"]
            except KeyError:
                print("Unexpected response from server:", resp1.json())
                input("Press Enter to continue...")
                return

            r1_inv = pow(r1, -1, p - 1)
            unblinded1 = pow(blinded2, r1_inv, p)

            try:
                resp2 = requests.post(f"{SERVER}/eval/step2", json={"uid": UID, "did": DID, "unblinded1": unblinded1}).json()
                print("Student Data: ", resp2["query_result"])
            except requests.exceptions.HTTPError as e:
                print("Step 2 failed:", e.response.json()["detail"])
                input("Press Enter to continue...")
                return
        
        elif choice == 3:
            dataEntryType = int(input("Is the data for new students (1) or existing students (2)? "))
            SData = ast.literal_eval(input("Enter student data in the format {DataID1:'Student Data 1', DataID2:'Student Data 2'}. Input any integer for DataID if inputting new data: "))
            
            try:
                resp1 = requests.post(f"{SERVER}/edit/step1", json={"dataEntryType": dataEntryType, "SData": SData}).json()
            except requests.exceptions.HTTPError as e:
                print("Step 1 failed:", e.response.json()["detail"])
                input("Press Enter to continue...")
                return
            
            print("Student database successfully edited ")
            if dataEntryType == 1: # if new student data is added
                print("with the following new DataIDs: ", resp1["newDataIDList"])
            

            print("===== Encrypted Index Database Editing =====")
            entries = int(input("Enter the number of index(es) you would like to edit: "))
            for i in range(entries):
                index = int(input("Enter an index to add or edit: "))
                hashed_index = hash_int(index) % p
                r1 = random_coprime(p - 1)

                blinded = pow(hashed_index, DK * r1, p)

                try:
                    resp2 = requests.post(
                        f"{SERVER}/edit/step2",
                        json={"uid": UID, "did": DID, "blinded": blinded}
                    )
                    resp2.raise_for_status()
                except requests.exceptions.HTTPError as e:
                    print("Step 2 failed:", e.response.json()["detail"])
                    input("Press Enter to continue...")
                    return
                
                try:
                    blinded2 = resp2.json()["blinded2"]
                except KeyError:
                    print("Unexpected response from server:", resp2.json())
                    input("Press Enter to continue...")
                    return

                r1_inv = pow(r1, -1, p - 1)
                unblinded1 = pow(blinded2, r1_inv, p)
                addOrRemove = int(input("Would you like to (1) add or (2) remove Data ID(s) from the index: "))
                DataID = [dataID.strip() for dataID in input("Enter DataID list separated by commas: ").split(",")]
                try:
                    resp3 = requests.post(f"{SERVER}/edit/step3", json={"uid": UID, "did": DID, "unblinded1": unblinded1, "addOrRemove": addOrRemove, "DataID": DataID}).json()
                    print("Index edit", resp3["result"])
                except requests.exceptions.HTTPError as e:
                    print("Step 3 failed:", e.response.json()["detail"])
                    input("Press Enter to continue...")
                    return

        elif choice == 4:
            print("Goodbye!")
            break
        
        else:
                print("Invalid choice.")

p = requests.get(f"{SERVER}/config").json()["p"]
primeList = primes.upto(104729)

UID, DID, DK = init_reg()
fn_selection(UID, DID, DK)