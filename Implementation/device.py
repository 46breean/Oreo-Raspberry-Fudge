import requests, random, math, hashlib, socket, sys, json, ast, pickle, os, base64
from primePy import primes # pyright: ignore[reportMissingTypeStubs]
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa

SERVER = "http://172.22.13.14:8000"

state: dict[str, int|str|dsa.DSAPrivateKey|dsa.DSAPublicKey|bytes] = {}

def save_state(state: dict[str, int|str|dsa.DSAPrivateKey|dsa.DSAPublicKey|bytes], filename:str ='client_state.pk1'):
    with open(filename, "wb") as f:
        pickle.dump(state, f)

def load_state(filename:str = 'client_state.pk1'):
    if not os.path.exists(filename):
        return None
    with open(filename, "rb") as f:
        return pickle.load(f)

def hash_int(x: int):
    m = hashlib.sha256()
    m.update(str(x).encode())
    return int(m.hexdigest(), 16)

def random_coprime(p_minus_1: int):
    while True:
        r = random.randint(2, p_minus_1)
        if math.gcd(r, p_minus_1) == 1:
            return r

def get_local_ip():
    ip: str
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def init_reg():
    uid: int
    did: int
    admin_did: int
    dk: int
    admin_ip: str
    admin_port: int
    
    while True:
        print("\nSign Up: Register new device")

        uid = int(input("Enter your UID: "))
        admin_did = int(input("Enter your administrator DID: "))

        try:
            loc = requests.get(
                f"{SERVER}/device_location",
                params={"uid": uid, "did": admin_did}
            )
            loc.raise_for_status()
            admin_info = loc.json()
            admin_ip = admin_info["ip"]
            admin_port = admin_info["port"]
        except requests.exceptions.HTTPError as e:
            print("Could not find admin device:", e.response.json()["detail"])
            sys.exit(1)
        
        devicePrivateKey = dsa.generate_private_key(key_size=2048)
        deviceCert = devicePrivateKey.public_key()

        # connect to admin device
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"Connecting to administrator device at {admin_ip}:{admin_port} for registration...")
            s.connect((admin_ip, admin_port))
            deviceCert_bytes = deviceCert.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            deviceCert_str = base64.b64encode(deviceCert_bytes).decode()
            data = {"deviceMsg": "Register New Device", "deviceCert": deviceCert_str}
            s.sendall(json.dumps(data).encode())
            print("Connected; awaiting response...")
            admin_reply = s.recv(4096).decode()
            if admin_reply == "REJECTED":
                print("[Administrator] Registration Request Rejected.")
                sys.exit()
            else:
                adminReply = json.loads(admin_reply)
                did, dk, deviceSignature_str = adminReply["DID"], adminReply["DK"], str(adminReply["deviceSignature_str"])
                deviceSignature = base64.b64decode(deviceSignature_str.encode())
                print(f"[Administrator] Device registration for DID {did} completed.")

        return uid, did, admin_did, dk, admin_ip, admin_port, devicePrivateKey, deviceCert, deviceSignature

def fn_selection(uid: int, did: int, dk: int, adminip: str, adminport: int, deviceprivatekey: dsa.DSAPrivateKey, devicecert: dsa.DSAPublicKey, devicesignature: bytes):
    while True:
        print("\nDevice Menu:")
        print("1. Revoke device")
        print("2. Evaluate and Query")
        print("3. Edit Database")
        print("4. Exit")
        choice = int(input("Select function: "))

        if choice == 1:
            revoke_did: int
            try:
                revoke_list = requests.get(
                    f"{SERVER}/revoke_list",
                    params = {"uid": uid, "did": did}
                )
                revoke_list.raise_for_status()
                did_list = revoke_list.json()["dids"]
            except requests.exceptions.HTTPError as e:
                print ("Current device not found")
                sys.exit(1)
            
            print(f"DIDs of registered, not yet revoked devices: {did_list}")
            did_selection = int(input("Select DID to revoke: "))
            revoke_did = did_selection
            message_str = f"Revoke{revoke_did}"
            message_bytes = message_str.encode()
            msgSignature = deviceprivatekey.sign(message_bytes, hashes.SHA256())
            msgSignature_str = base64.b64encode(msgSignature).decode()
            deviceCert_bytes = devicecert.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            deviceCert_str = base64.b64encode(deviceCert_bytes).decode()
            deviceSignature_str = base64.b64encode(devicesignature).decode()
            revocation = requests.post(
                f"{SERVER}/revoke",
                json={"uid": uid, "did": did, "revoke_did": revoke_did, "message_str": message_str, "msgSignature_str": msgSignature_str, "deviceCert_str": deviceCert_str, "deviceSignature_str": deviceSignature_str}
            ).json()
            print(revocation)
        
        elif choice == 2:
            queryResult: dict[str, str] = {}
            data: dict[str, str|int|dict[str, str]]
            
            print("You can query in 3 ways:")
            print("1. Single query: results that satisfy the given condition")
            print("2. AND query: only results that satisfy all given conditions")
            print("3. OR query: results that satisfy at least one given condition (i.e. multiple discrete single queries)")
            queryType = int(input("Select your query type (1/2/3): "))

            indexes = [index.strip() for index in input("Enter student data quer(ies) separated by commas: ").split(",")]
            for index in indexes:
                intIndex = int(index)
                hashed_index = hash_int(intIndex) % p

                # blinding
                r1 = random_coprime(p - 1)
                blinded = pow(hashed_index, dk * r1, p)

                #server-blinding
                try:
                    resp1 = requests.post(
                        f"{SERVER}/eval/step1", 
                        json={"uid": uid, "did": did, "blinded": blinded}
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

                # unblinding
                r1_inv = pow(r1, -1, p - 1)
                unblinded1 = pow(blinded2, r1_inv, p)

                # receive query result
                try:
                    resp2 = requests.post(
                        f"{SERVER}/eval/step2", 
                        json={"uid": uid, "did": did, "unblinded1": unblinded1}
                    ).json()
                    tempQueryResult = resp2["query_result"]  # dict[dataID:studentinfo] (encrypted)
                except requests.exceptions.HTTPError as e:
                    print("Step 2 failed:", e.response.json()["detail"])
                    input("Press Enter to continue...")
                    return
                
                if queryType == 1 or queryType == 3:
                        queryResult = queryResult|tempQueryResult
                elif queryType == 2:
                    if not queryResult:
                        queryResult = tempQueryResult
                    else:
                        queryResult = {k:tempQueryResult[k] for k in queryResult if k in tempQueryResult}

            message_str = "Decrypt Data"
            message_bytes = message_str.encode()
            msgSignature = deviceprivatekey.sign(message_bytes, hashes.SHA256())
            msgSignature_str = base64.b64encode(msgSignature).decode()
            deviceCert_bytes = devicecert.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            deviceCert_str = base64.b64encode(deviceCert_bytes).decode()
            deviceSignature_str = base64.b64encode(devicesignature).decode()
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                print(f"Connecting to administrator device at {adminip}:{adminport} for student data decryption...")
                s.connect((adminip, adminport))
                data = {"deviceMsg": "Decrypt Data", "DID": did, "StudentData": queryResult, "message_str":message_str,"msgSignature_str": msgSignature_str, "deviceCert_str": deviceCert_str, "deviceSignature_str": deviceSignature_str}
                s.sendall(json.dumps(data).encode())
                SData = json.loads(s.recv(4096).decode())
                if SData == b"REJECTED":
                    print("[Administrator] Decryption Request Rejected, device has been revoked.")
                    sys.exit(1)
                else:
                    print("[Administrator] Decryption Request Accepted.")
                    StudentData:dict[int,str] = {}
                    for DataID, Data in list(SData.items()):
                        StudentData[int(DataID)] = Data
        
            print(f"Student Data requested: \n{StudentData}")

        elif choice == 3:
            dataEntryType = int(input("Is the data for new students (1) or existing students (2)? "))
            SData = ast.literal_eval(input("Enter student data in the format {DataID1:'Student Data 1', DataID2:'Student Data 2'}. Input any integer for DataID if inputting new data: "))
            
            message_str = "Encrypt Data"
            message_bytes = message_str.encode()
            msgSignature = deviceprivatekey.sign(message_bytes, hashes.SHA256())
            msgSignature_str = base64.b64encode(msgSignature).decode()
            deviceCert_bytes = devicecert.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            deviceCert_str = base64.b64encode(deviceCert_bytes).decode()
            deviceSignature_str = base64.b64encode(devicesignature).decode()

            # connect to admin device
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                print(f"Connecting to administrator device at {adminip}:{adminport} for student data encryption...")
                s.connect((adminip, adminport))
                data = {"deviceMsg": "Encrypt Data", "DID": did, "StudentData": SData, "message_str":message_str,"msgSignature_str": msgSignature_str, "deviceCert_str": deviceCert_str, "deviceSignature_str": deviceSignature_str}
                s.sendall(json.dumps(data).encode())
                SData = json.loads(s.recv(4096).decode())
                if SData == b"REJECTED":
                    print("[Administrator] Encryption Request Rejected. Press Enter to continue...")
                    return
                else:
                    print("[Administrator] Encryption Request Accepted.")

            try:
                resp1 = requests.post(
                    f"{SERVER}/edit/step1", 
                    json={"dataEntryType": dataEntryType, "SData": SData}
                )
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
            
            if dataEntryType == 1: # if new student data is added
                print(f"Student database successfully edited with the following new DataIDs: {newDataIDList}")
            else:
                print("Student database successfully edited.")
            
            print("\n===== Encrypted Index Database Editing =====")
            indexes = [index.strip() for index in input("Enter list of indexes you would like to edit, separated by commas: ").split(",")]
            entries = len(indexes)
            for i in range(entries):
                index = int(indexes[i])
                print(f"Currently editing: index {index}.")
                hashed_index = hash_int(index) % p
                r1 = random_coprime(p - 1)

                blinded = pow(hashed_index, dk * r1, p)

                try:
                    resp2 = requests.post(
                        f"{SERVER}/edit/step2",
                        json={"uid": uid, "did": did, "blinded": blinded}
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
                print("You can edit this index in 2 ways: ")
                print("1. Add Data IDs only")
                print("2. Remove Data IDs only")
                addOrRemove = int(input("Select your editing type: "))
                dataIDs = [DataID.strip() for DataID in input("Enter the Data IDs you would like to add/remove, separated by commas: ").split(",")]
                try:
                    resp3 = requests.post(
                        f"{SERVER}/edit/step3", 
                        json={"uid": uid, "did": did, "unblinded1": unblinded1, "addOrRemove": addOrRemove, "dataIDs": dataIDs}
                    ).json()
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

def runClient():
    # start_state = load_state()
    # if start_state:
    #     uid = start_state["UID"]
    #     did = start_state["DID"]
    #     admindid = start_state["adminDID"]
    #     dk = start_state["DK"]
    #     adminip = start_state["adminIP"]
    #     adminport = start_state["adminPort"]
    #     deviceprivatekey = start_state["devicePrivateKey"]
    #     deviceCert = start_state["deviceCert"]
    #     deviceSignature = start_state["deviceSignature"]
    #     print("Saved state loaded.")
    # else:
    #     print("Fresh state loaded.")
    uid, did, admindid, dk, adminip, adminport, deviceprivatekey, deviceCert, deviceSignature = init_reg()
        # state["UID"] = uid
        # state["DID"] = did
        # state["adminDID"] = admindid
        # state["DK"] = dk
        # state["adminIP"] = adminip
        # state["adminPort"] = adminport
        # state["devicePrivateKey"] = deviceprivatekey
        # state["deviceCert"] = deviceCert
        # state["deviceSignature"] = deviceSignature
        # save_state(state)
    return uid, did, admindid, dk, adminip, adminport, deviceprivatekey, deviceCert, deviceSignature

p:int = requests.get(f"{SERVER}/config").json()["p"]
primeList:list[int] = primes.upto(104729) # pyright: ignore[reportUnknownMemberType]

UID, DID, adminDID, DK, adminIP, adminPort, devicePrivateKey, deviceCert, deviceSignature = runClient()
fn_selection(UID, DID, DK, adminIP, adminPort, devicePrivateKey, deviceCert, deviceSignature)