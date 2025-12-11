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

def hash_str(x: str):
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

# lambda(x) helpers and validator

P_MINUS_1_FACTORS: dict[int,int] = {
    2: 3,
    257: 1,
    8677: 1,
    1681411: 1
}

LAMBDA_THRESHOLD = 3749528034479

def trial_factor(n: int, limit: int = 200000) -> dict[int,int]:
    factors: dict[int,int] = {}
    while n % 2 == 0:
        factors[2] = factors.get(2, 0) + 1
        n //= 2
    f = 3
    while f <= limit and f * f <= n:
        while n % f == 0:
            factors[f] = factors.get(f, 0) + 1
            n //= f
        f += 2
    if n != 1:
        factors[n] = factors.get(n, 0) + 1
    return factors

def multiplicative_order_with_factors(x: int, p_val: int, factors: dict[int,int]) -> int:
    if x % p_val == 0:
        return 1
    ord_val = p_val - 1
    for q, exp in list(factors.items()):
        for _ in range(exp):
            candidate = ord_val // q
            if pow(x, candidate, p_val) == 1:
                ord_val = candidate
            else:
                break
    return ord_val

def multiplicative_order_slow(x: int, p_val: int) -> int:
    facs = trial_factor(p_val - 1, limit=200000)
    return multiplicative_order_with_factors(x, p_val, facs)

def lambda_of_x(x: int, p_val: int, known_factors: dict[int,int]|None = None) -> int:
    if known_factors and len(known_factors) > 0:
        return multiplicative_order_with_factors(x, p_val, known_factors)
    else:
        return multiplicative_order_slow(x, p_val)

def validate_x_or_raise(x: int, p_val: int, threshold: int = LAMBDA_THRESHOLD,
                        known_factors: dict[int,int]|None = None) -> None:
    lam = lambda_of_x(x, p_val, known_factors)
    if lam < threshold:
        raise ValueError(f"Query value x={x} rejected: λ(x)={lam} < threshold {threshold}")

# end of lambda(x) helpers

def registration():
    uid: int
    did: int
    dk: int
    admin_ip: str
    admin_port: int
    
    while True:
        print("\nSign Up: Register new device")

        school_name = str(input("Enter your school name: "))
        device_name = str(input("Enter your device name: "))

        try:
            loc = requests.get(
                f"{SERVER}/admin_device_location",
                params={"school_name": school_name}
            )
            loc.raise_for_status()
            admin_info = loc.json()
            admin_ip = admin_info["ip"]
            admin_port = admin_info["port"]
            uid = admin_info["uid"]
        except requests.exceptions.HTTPError as e:
            print("Could not find admin device:", e.response.json()["detail"])
            sys.exit(1)
        
        devicePrivateKey = dsa.generate_private_key(key_size=2048)
        deviceCert = devicePrivateKey.public_key()

        # connect to admin device
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"\nConnecting to administrator device at {admin_ip}:{admin_port} for registration...")
            s.connect((admin_ip, admin_port))
            deviceCert_bytes = deviceCert.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            deviceCert_str = base64.b64encode(deviceCert_bytes).decode()
            data = {"deviceMsg": "Register New Device", "deviceCert": deviceCert_str, "deviceName": device_name}
            s.sendall(json.dumps(data).encode())
            print("Connected; awaiting response...")
            admin_reply = s.recv(4096).decode()
            if admin_reply == "REJECTED":
                print("[Administrator] Registration Request Rejected.")
                sys.exit(1)
            elif admin_reply == "Invalid name":
                print("Device name already exists. Please choose a different device name.")
                continue
            else:
                adminReply = json.loads(admin_reply)
                did, dk, deviceSignature_str = adminReply["DID"], adminReply["DK"], str(adminReply["deviceSignature_str"])
                deviceSignature = base64.b64decode(deviceSignature_str.encode())
                print(f"\n[Administrator] Device registration for DID {did} completed.")

        return uid, did, dk, admin_ip, admin_port, devicePrivateKey, deviceCert, deviceSignature

def fn_selection(uid: int, did: int, dk: int, adminip: str, adminport: int, deviceprivatekey: dsa.DSAPrivateKey, devicecert: dsa.DSAPublicKey, devicesignature: bytes):
    while True:
        print("\nDevice Menu:")
        print("1. Evaluate and Query")
        print("2. Edit Database")
        print("3. Exit")
        try:
            choice = int(input("Select function: "))
                
            if choice == 1:
                queryResult: dict[str, str] = {}
                data: dict[str, str|int|dict[str, str]]
                
                print("\nSelect your query type:")
                print("1. Single query: results that satisfy the given condition")
                print("2. AND query: only results that satisfy all given conditions")
                print("3. OR query: results that satisfy at least one given condition (i.e. multiple discrete single queries)")
                queryType = int(input("Select your query type (1/2/3): "))

                indexes = [index.strip() for index in input("Enter student data quer(ies) separated by commas: ").split(",")]
                for index in indexes:
                    intIndex = str(index)
                    hashed_index = hash_str(intIndex) % p

                    # validate lambda(x) for hashed_index
                    try:
                        validate_x_or_raise(hashed_index, p, known_factors=P_MINUS_1_FACTORS)
                    except ValueError as e:
                        print("Invalid query index:", e)
                        print("Please choose a different query.")
                        continue

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
                    print(f"\nConnecting to administrator device at {adminip}:{adminport} for student data decryption...")
                    s.connect((adminip, adminport))
                    data = {"deviceMsg": "Decrypt Data", "DID": did, "StudentData": queryResult, "message_str":message_str,"msgSignature_str": msgSignature_str, "deviceCert_str": deviceCert_str, "deviceSignature_str": deviceSignature_str}
                    s.sendall(json.dumps(data).encode())
                    SData = s.recv(4096).decode()
                    if SData == "REJECTED":
                        print("[Administrator] Decryption Request Rejected, device has been revoked.")
                        sys.exit(1)
                    else:
                        SData = json.loads(SData)
                        print("[Administrator] Decryption Request Accepted.")
                        StudentData:dict[int,str] = {}
                        for DataID, Data in list(SData.items()):
                            StudentData[int(DataID)] = Data
            
                print(f"\nStudent Data requested: \n{StudentData}")


            elif choice == 2:

                database = int(input("\nWould you like to edit student database (1) or encrypted index database (2)? "))
                try: 
                    if database == 1:
                        dataEntryType = int(input("Is the data for new students (1) or existing students (2)? "))

                        while True:

                            if dataEntryType == 1:
                                print("Format: {0:'Student Data 1', 0:'Student Data 2'}")
                                SData = ast.literal_eval(input("Enter student data to be added: "))

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

                                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                                    print(f"\nConnecting to administrator device at {adminip}:{adminport} for student data encryption...")
                                    s.connect((adminip, adminport))
                                    data = {"deviceMsg": "Encrypt Data", "DID": did, "StudentData": SData, "message_str":message_str,"msgSignature_str": msgSignature_str, "deviceCert_str": deviceCert_str, "deviceSignature_str": deviceSignature_str}
                                    s.sendall(json.dumps(data).encode())
                                    SData = s.recv(4096).decode()
                                    if SData == "REJECTED":
                                        print("[Administrator] Encryption Request Rejected.")
                                        sys.exit(1)
                                    else:
                                        SData = json.loads(SData)
                                        print("[Administrator] Encryption Request Accepted.")

                                try:
                                    resp1 = requests.post(
                                        f"{SERVER}/edit/new",
                                        json = {"uid": uid, "did": did, "SData":SData}
                                    )
                                    resp1.raise_for_status()
                                except requests.exceptions.HTTPError as e:
                                    print("Editing failed:", e.response.json()["detail"])
                                    input("Press Enter to continue...")
                                    continue

                            
                                try:
                                    newDataIDList = resp1.json()["newDataIDList"]
                                    print(f"DataIDs of new students: {newDataIDList}")
                                except KeyError:
                                    print("\nUnexpected response from server:", resp1.json())
                                    input("Press Enter to continue...")
                                    return
            
                            elif dataEntryType == 2:

                                try:
                                    print("Format: 1 2 3 4 5 (e.g.)")
                                    dataIDs = str(input("Enter DataIDs separated by space: "))
                                    dataIDs = list(map(int, dataIDs.split()))
                                    
                                    try:
                                        resp1 = requests.post(
                                            f"{SERVER}/edit/existing",
                                            json = {"uid": uid, "did": did, "dataIDs": dataIDs}
                                        )
                                        resp1.raise_for_status()
                                    except requests.exceptions.HTTPError as e:
                                        print("\nEditing failed:", e.response.json()["detail"])
                                        input("Press Enter to continue...")
                                        continue
                                    resp1 = resp1.json()
                                    resp1 = resp1["currentData"]
                                
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
                                        print(f"\nConnecting to administrator device at {adminip}:{adminport} for student data decryption...")
                                        s.connect((adminip, adminport))
                                        data = {"deviceMsg": "Decrypt Data", "DID": did, "StudentData": resp1, "message_str":message_str,"msgSignature_str": msgSignature_str, "deviceCert_str": deviceCert_str, "deviceSignature_str": deviceSignature_str}
                                        s.sendall(json.dumps(data).encode())
                                        SData = s.recv(4096).decode()
                                        if SData == "REJECTED":
                                            print("[Administrator] Decryption Request Rejected, device has been revoked.")
                                            sys.exit(1)
                                        else:
                                            SData = json.loads(SData)
                                            print("[Administrator] Decryption Request Accepted.\n ")
                                            StudentData:dict[int,str] = {}
                                            for DataID, Data in list(SData.items()):
                                                StudentData[int(DataID)] = Data

                                    print("Student data to be edited...")
                                    for key, value in StudentData.items():
                                        print(f"{key}: {value}")

                                    print("Format: {DataID1:'Student Data 1', DataID2:'Student Data 2'}")
                                    SData = ast.literal_eval(input("Enter student data to be added: "))

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

                                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                                        print(f"\nConnecting to administrator device at {adminip}:{adminport} for student data encryption...")
                                        s.connect((adminip, adminport))
                                        data = {"deviceMsg": "Encrypt Data", "DID": did, "StudentData": SData, "message_str":message_str,"msgSignature_str": msgSignature_str, "deviceCert_str": deviceCert_str, "deviceSignature_str": deviceSignature_str}
                                        s.sendall(json.dumps(data).encode())
                                        SData = s.recv(4096).decode()
                                        if SData == "REJECTED":
                                            print("[Administrator] Encryption Request Rejected.")
                                            sys.exit(1)
                                        else:
                                            SData = json.loads(SData)
                                            print("[Administrator] Encryption Request Accepted.")

                                    try:
                                        resp2 = requests.post(
                                            f"{SERVER}/edit/existing/update",
                                            json = {"uid": uid, "did": did, "SData": SData}
                                        )
                                        resp2.raise_for_status()
                                    except requests.exceptions.HTTPError as e:
                                        print("Editing failed:", e.response.json()["detail"])
                                        input("Press Enter to continue...")
                                        continue
                                except ValueError:
                                    print("\nPlease choose a valid DataID.")
                                    continue
                            
                            else:
                                print("Please select (1) or (2).")
                                continue

                            print("\nStudent database successfully edited.")
                            break

                    elif database == 2:
                        print("\n===== Encrypted Index Database Editing =====")
                        indexes = [index.strip() for index in input("Enter list of indexes you would like to edit, separated by commas: ").split(",")]
                        entries = len(indexes)
                        for i in range(entries):
                            index = str(indexes[i])
                            print(f"\nCurrently editing: index {index}.")
                            hashed_index = hash_str(index) % p

                            # validate lambda(x) for hashed_index
                            try:
                                validate_x_or_raise(hashed_index, p, known_factors=P_MINUS_1_FACTORS)
                            except ValueError as e:
                                print("Invalid index value:", e)
                                print("Please choose a different index.")
                                continue

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
                                continue
                            
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
                            addOrRemove = 0
                            while addOrRemove != 1 and addOrRemove != 2:
                                addOrRemove = int(input("Select your editing type: "))
                            dataIDs = [DataID.strip() for DataID in input("\nEnter the Data IDs you would like to add/remove, separated by commas: ").split(",")]
                            try:
                                resp3 = requests.post(
                                    f"{SERVER}/edit/step3", 
                                    json={"uid": uid, "did": did, "unblinded1": unblinded1, "addOrRemove": addOrRemove, "dataIDs": dataIDs}
                                ).json()
                                print(f"\nIndex edit, {resp3['result']}.")
                            except requests.exceptions.HTTPError as e:
                                print("Step 3 failed:", e.response.json()["detail"])
                                input("Press Enter to continue...")
                                return

                    else:
                        print("Please select (1) or (2).")
                
                except ValueError:
                    print("Please select (1) or (2).")
            
            elif choice == 3:
                print("Goodbye!")
                sys.exit(1)

            else:
                print("Please select a valid function.")
        except ValueError:
            print("Please enter a valid input.")

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
    uid, did, dk, adminip, adminport, deviceprivatekey, deviceCert, deviceSignature = registration()
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
    return uid, did, dk, adminip, adminport, deviceprivatekey, deviceCert, deviceSignature

p:int = requests.get(f"{SERVER}/config").json()["p"]
primeList:list[int] = primes.upto(104729) # pyright: ignore[reportUnknownMemberType]

UID, DID, DK, adminIP, adminPort, devicePrivateKey, deviceCert, deviceSignature = runClient()
fn_selection(UID, DID, DK, adminIP, adminPort, devicePrivateKey, deviceCert, deviceSignature)