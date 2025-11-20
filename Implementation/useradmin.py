from primePy import primes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import requests, random, math, hashlib, socket, sys, threading, json, base64, os, pickle

SERVER = "http://172.22.22.27:8000"

state: dict[str, int|list[int]|bytes] = {}

def save_state(state: dict[str, int|list[int]|bytes], filename:str ='useradmin_state.pk1'):
    with open(filename, "wb") as f:
        pickle.dump(state, f)

def load_state(filename:str = 'useradmin_state.pk1'):
    if not os.path.exists(filename):
        return None
    with open(filename, "rb") as f:
        return pickle.load(f)

def hash_int(x: int) -> int:
    m = hashlib.sha256()
    m.update(str(x).encode())
    return int(m.hexdigest(), 16)

def random_coprime(p_minus_1: int) -> int:
    while True:
        r = random.randint(2, p_minus_1)
        if math.gcd(r, p_minus_1) == 1:
            return r

def selfKeyDev():
    keyProduct: list[int] = [random.choice(primeList) for _ in range (100)]
    bitstring: list[int] = []
    base: int = 1
    unused: int = 1

    requirement = False
    while requirement == False:
        bitstring = [random.randint(0, 1) for _ in range(100)]
        if bitstring.count(1)>=50 and bitstring.count(1)<=70:
            requirement = True

    for i in range(100):
        if bitstring[i] == 1:
            base *= keyProduct[i]
        else:
            unused *= keyProduct[i]

    return base, unused, keyProduct

def regKeyDev(keyproduct:list[int]):
    bitstring: list[int] = []
    base: int = 1
    unused: int = 1

    requirement = False
    while requirement == False:
        bitstring = [random.randint(0, 1) for _ in range(100)]
        if bitstring.count(1)>=50 and bitstring.count(1)<=70:
            requirement = True

    for i in range(100):
        if bitstring[i] == 1:
            base *= keyproduct[i]
        else:
            unused *= keyproduct[i]

    return base, unused

def handle_registration(uid:int, did:int, keyproduct:list[int], addr:int) -> list[int]|bytes:    
    print(f"Incoming registration request from {addr}.")
    regreq_ans = int(input("Type 1 to accept request, type any other key to reject request: "))

    if regreq_ans == 1:
        while True:
            new_dk, unused = regKeyDev(keyproduct)
            register = requests.post(
                f"{SERVER}/register",
                json={"uid": uid, "did": did, "unused": unused}
            )
            if register.status_code == 409:
                print("DK invalid, retrying...")
                continue

            try:
                register.raise_for_status()
                register_data = register.json()
                break
            except requests.exceptions.HTTPError as e:
                try:
                    # Try to extract JSON error detail
                    err_detail = e.response.json().get("detail", str(e))
                except ValueError:
                    # If response is not JSON
                    err_detail = e.response.text or str(e)
                print("Registration failed:", err_detail)
                continue  # try again or break depending on your logic

        new_did:int = register_data["new_did"]
        data = [new_did, new_dk]

    else:
        data = b"REJECTED"

    return data

def encryptData(Data:str, schoolKey:bytes) -> str:
    aes = AESGCMSIV(schoolKey)
    nonce = b"\x00"*12
    plaintext = Data.encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return base64.b64encode(ciphertext).decode("utf-8")

def decryptData(Data:str, schoolKey:bytes) -> str:
    aes = AESGCMSIV(schoolKey)
    nonce = b"\x00"*12
    ciphertext = base64.b64decode(Data)
    plaintext = aes.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def inbound_socket(uid:int, did:int, keyProduct:list[int]):
    regData: dict[str,int|list[int]]
    plaintextData: dict[str, str]
    ciphertextData: dict[str, str]
    
    HOST = get_local_ip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        s.listen()
        PORT = s.getsockname()[-1]
        requests.post(
            f"{SERVER}/announce", 
            json={"uid": uid, "did": did, "ip": HOST, "port": PORT}
        )
        print(f"Listener started on {HOST}:{PORT}...")

        while True:
            conn, addr = s.accept()
            with conn:
                data = json.loads(conn.recv(1024).decode())
                deviceMsg  = data["deviceMsg"]

                if deviceMsg == "Register New Device":                    
                    data = handle_registration(uid, did, keyProduct, addr)
                    regData = {"DID": data[0], "DK": data[1]}
                    conn.sendall(json.dumps(regData).encode())
                    print(f"Device registration for DID {data[0]} completed.")
                
                elif deviceMsg == "Encrypt Data":
                    did = data["DID"]
                    plaintextData = data["StudentData"]
                    ciphertextData = {}
                    print(f"Incoming data encryption request from (device name) (DID {did}).")
                    regreq_ans = int(input("Type 1 to accept request, type any other key to reject request: "))
                    if regreq_ans == 1:
                        for DataID, Data in plaintextData.items():
                            ciphertextData[DataID] = encryptData(Data, schoolKey)
                    else:
                        data = b"REJECTED"
                    print("Encryption successful.")
                    conn.sendall(json.dumps(ciphertextData).encode())
                
                elif deviceMsg == "Decrypt Data":
                    did = data["DID"]
                    ciphertextData = data["StudentData"]
                    plaintextData = {}
                    print(f"Incoming data decryption request from (device name) (DID {did}).")
                    regreq_ans = int(input("Type 1 to accept request, type any other key to reject request: "))
                    if regreq_ans == 1:
                        for DataID, Data in ciphertextData.items():
                            print(Data)
                            plaintextData[DataID] = decryptData(Data, schoolKey)
                    else:
                        data = b"REJECTED"
                    print("Decryption successful.")
                    conn.sendall(json.dumps(plaintextData).encode())
                
                else:
                    print("This functionality has not yet been programmed for.")

def init_reg():
    uid: int
    did: int
    dk: int
    keyproduct: list[int]
    schoolKey: bytes
    
    while True:
        print("\nSign Up: Initialise user")
        input("Press Enter to start initialisation: ")
        name = "Administrator"
        print(f"Device name: {name}")
        dk, unused, keyproduct = selfKeyDev()

        #Registration with server
        init = requests.post(
            f"{SERVER}/super_init", 
            json={"name": name, "unused": unused}
        ).json()
        uid, did = init["UID"], init["DID"]

        #Obtaining school encryption key
        try:
            loc = requests.get(
                f"{SERVER}/device_location",
                params={"uid": 1, "did": 1}
            )
            loc.raise_for_status()
            referral_info = loc.json()
            referral_ip = referral_info["ip"]
            referral_port = referral_info["port"]
        except requests.exceptions.HTTPError as e:
            print("Could not find server administrator:", e.response.json()["detail"])
            sys.exit(1)
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"Connecting to server administrator at {referral_ip}:{referral_port} to obtain school encryption key...")
            s.connect((referral_ip, referral_port))
            data = json.dumps({"deviceMsg": "Obtain school encryption key", "UID": uid, "DID":did}).encode()
            s.sendall(data)
            schoolKey_int = int(json.loads(s.recv(4096).decode()))
            schoolKey = schoolKey_int.to_bytes(32, "big")

        print(f"User registration completed for UID {uid}.")
        print(f"User Administrator initialised with UID {uid}, DID {did}, School Encryption Key {schoolKey_int}.")

        return uid, did, dk, keyproduct, schoolKey

p = requests.get(f"{SERVER}/config").json()["p"]
primeList = primes.upto(104729)

def runUserAdmin():
    start_state = load_state()
    if start_state:
        uid = start_state["UID"]
        did = start_state["DID"]
        dk = start_state["DK"]
        keyproduct = start_state["keyProduct"]
        schoolkey = start_state["schoolKey"]
        print("Saved state loaded.")
    else:
        print("Fresh state loaded.")
        uid, did, dk, keyproduct, schoolkey = init_reg()
        state["UID"] = uid
        state["DID"] = did
        state["DK"] = dk
        state["keyProduct"] = keyproduct
        state["schoolKey"] = schoolkey
        save_state(state)
    return uid, did, dk, keyproduct, schoolkey

UID, DID, DK, keyProduct, schoolKey = runUserAdmin()

#start listener
listener_thread = threading.Thread(target=inbound_socket, args=(UID, DID, keyProduct), daemon=False)
listener_thread.start()