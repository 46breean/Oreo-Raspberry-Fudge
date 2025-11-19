import requests, random, math, hashlib, socket, sys, threading, time, subprocess, tempfile, os, json, ast
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from primePy import primes

SERVER = "http://127.0.0.1:8000"

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

# def encryptMessage(schoolKey, plainText, aad=b""):
#     nonce = os.urandom(12)
#     aesgcm = AESGCM(schoolKey)
#     ciphertext = aesgcm.encrypt(nonce, plainText, aad)
#     return nonce, ciphertext

# def decryptMessage(schoolKey, nonce, cipherText, aad=b""):
#     aesgcm = AESGCM(schoolKey)
#     plaintext = aesgcm.decrypt(nonce, cipherText, aad)
#     return plaintext

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def inbound_socket(UID, DID, keyproduct):

    HOST = get_local_ip()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        s.listen()

        PORT = s.getsockname()[-1]
        requests.post(f"{SERVER}/announce", params={"uid": UID, "did": DID, "ip": HOST, "port": PORT})

        print(f"[Device {DID}] Listener started on {HOST}:{PORT}...")

        while True:
            conn, addr = s.accept()
            with conn:
                newdev_msg = conn.recv(1024).decode()
                if not newdev_msg:
                    continue

                tmp = tempfile.NamedTemporaryFile(delete=False)
                tmp_path = tmp.name
                tmp.close()

                subprocess.Popen([
                    "start", "cmd", "/c",
                    sys.executable, "registration.py",
                    str(UID), str(DID),
                    str(addr),
                    newdev_msg,
                    str(keyproduct), str(tmp_path)
                ], shell=True)

                while not os.path.exists(tmp_path) or os.path.getsize(tmp_path) == 0:
                    time.sleep(0.2)

                with open(tmp_path, "r") as f:
                    data = json.load(f)

                os.remove(tmp_path)

                data = {"DID": data[0], "DK": data[1], "unused": data[2]}
                data["keyproduct"] = keyproduct
                data_to_send = json.dumps(data)

                conn.sendall(data_to_send.encode())

def init_reg():
    
    while True:

        try:

            print("\nSign Up:")
            print("1. Initialise user")
            print("2. Register new device")
            choice = int(input("Select function: "))

            if choice == 1:
                name = input("Enter device name: ")
                dk, unused, keyproduct = keyDev()
                init = requests.post(f"{SERVER}/init", params={"name": name, "unused": unused}).json()
                uid, did = init["UID"], init["DID"]
                print("Initialised:", init)

                print (f"UID: {uid}")

                #start listener
                listener_thread = threading.Thread(target=inbound_socket, args=(uid, did, keyproduct), daemon=True)
                listener_thread.start()
                time.sleep(0.5) 

                return uid, did, dk

            elif choice == 2:
                uid = input("Enter your UID: ")
                referral_did = input("Enter the DID of your referral device: ")

                try:
                    loc = requests.get(
                        f"{SERVER}/device_location",
                        params={"uid": uid, "did": referral_did}
                    )
                    loc.raise_for_status()
                    referral_info = loc.json()
                    referral_ip = referral_info["ip"]
                    referral_port = referral_info["port"]
                except requests.exceptions.HTTPError as e:
                    print("Could not find referral device:", e.response.json()["detail"])
                    sys.exit(1)

                # connect to referral device
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    print(f"Connecting to referral device at {referral_ip}:{referral_port}...")
                    s.connect((referral_ip, referral_port))
                    s.sendall(b"Registration Request")
                    newdev_msg = s.recv(4096).decode()
                    if newdev_msg == b"REJECTED":
                        print("Registration Request Rejected")
                        sys.exit()
                    else:
                        data = json.loads(newdev_msg)
                        did, dk, unused, keyproduct = (
                            data["DID"],
                            data["DK"],
                            data["unused"],
                            data["keyproduct"]
                        )
                        did, dk, unused, keyproduct = int(did), int(dk), int(unused), list(keyproduct)
                    
                #start listener
                listener_thread = threading.Thread(target=inbound_socket, args=(uid, did, keyproduct), daemon=True)
                listener_thread.start()
                time.sleep(0.5) 

                return uid, did, dk
            
        except ValueError:
            print("Invalid input. Please try again.")
            continue  

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
            print("You can query in 3 ways:")
            print("1. Single query: results that satisfy the given condition")
            print("2. AND query: only results that satisfy all given conditions")
            print("3. OR query: results that satisfy at least one given condition (i.e. multiple discrete single queries)")
            queryType = int(input("Enter your choice (1/2/3): "))
            
            queryResult = {}

            indexes = [index.strip() for index in input("Enter student data quer(ies) separated by commas: ").split(",")]
            for index in indexes:
                intIndex = int(index)
                hashed_index = hash_int(intIndex) % p
                r1 = random_coprime(p - 1)

                blinded = pow(hashed_index, DK * r1, p)

                try:
                    resp1 = requests.post(f"{SERVER}/eval/step1", json={"uid": UID, "did": DID, "blinded": blinded})
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
                    tempQueryResult = resp2["query_result"]
                except requests.exceptions.HTTPError as e:
                    print("Step 2 failed:", e.response.json()["detail"])
                    input("Press Enter to continue...")
                    return
                
                if queryType in (1,3):
                        queryResult = queryResult|tempQueryResult
                elif queryType == 2:
                    if not queryResult:
                        queryResult = tempQueryResult
                    else:
                        queryResult = {int(k):tempQueryResult[k] for k in queryResult if k in tempQueryResult}
        
            print(f"Student Data: {queryResult}")

        elif choice == 3:
            dataEntryType = int(input("Is the data for new students (1) or existing students (2)? "))
            SData = ast.literal_eval(input("Enter student data in the format {DataID1:'Student Data 1', DataID2:'Student Data 2'}. Input any integer for DataID if inputting data for new students: "))
            # for DataID, studentData in SData:
            #     SData[DataID] = encryptMessage(SKey, studentData, aad)

            try:
                resp1 = requests.post(f"{SERVER}/edit/step1", json={"dataEntryType": dataEntryType, "SData": SData})
                resp1.raise_for_status()
            except requests.exceptions.HTTPError as e:
                print("Step 1 failed:", e.response.json()["detail"])
                input("Press Enter to continue...")
                return
            
            try:
                newDataIDList = resp1.json()["newDataIDList"]
            except KeyError:
                print("Unexpected response from server:", resp1.json())
                input("Press Enter to continue...")
                return
            
            print("Student database successfully edited ")
            if dataEntryType == 1: # if new student data is added
                print(f"with the following new DataIDs: {newDataIDList}")
            
            print("\n===== Encrypted Index Database Editing =====")
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