from primePy import primes # pyright: ignore[reportMissingTypeStubs]
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from typing import cast
import requests, random, math, hashlib, socket, sys, threading, json, base64, os, pickle

SERVER = "http://172.22.13.14:8000"

state: dict[str, int|list[int]|bytes|dsa.DSAPrivateKey|dsa.DSAPublicKey] = {}

def save_state(state: dict[str, int|list[int]|bytes|dsa.DSAPrivateKey|dsa.DSAPublicKey], filename:str ='useradmin_state.pk1'):
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

def generateDeviceSignature(deviceCert: dsa.DSAPublicKey):
    deviceCert_bytes = deviceCert.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    deviceSignature = schoolPrivateKey.sign(deviceCert_bytes, hashes.SHA256())
    return deviceSignature

def encryptData(Data:str, schoolEncKey:bytes) -> str:
    aes = AESGCMSIV(schoolEncKey)
    nonce = b"\x00"*12
    plaintext = Data.encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return base64.b64encode(ciphertext).decode()

def decryptData(Data:str, schoolEncKey:bytes) -> str:
    aes = AESGCMSIV(schoolEncKey)
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
    regData: dict[str,int|str]
    plaintextData: dict[str, str]
    ciphertextData: dict[str, str]
    
    HOST = get_local_ip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        s.listen()
        PORT = s.getsockname()[-1]
        resp = requests.post(
            f"{SERVER}/announce", 
            json={"uid": uid, "did": did, "ip": HOST, "port": PORT}
        ).json()
        print(resp["result"])
        print(f"Listener started on {HOST}:{PORT}...")

        while True:
            conn, addr = s.accept()
            with conn:
                data = json.loads(conn.recv(4096).decode())
                deviceMsg:str = data["deviceMsg"]

                if deviceMsg == "Register New Device":
                    deviceCert_str:str = data["deviceCert"]
                    data = handle_registration(uid, did, keyProduct, addr)
                    deviceCert_bytes = base64.b64decode(deviceCert_str.encode())
                    deviceCert_publicKeyTypes = serialization.load_pem_public_key(deviceCert_bytes)
                    deviceCert = cast(dsa.DSAPublicKey, deviceCert_publicKeyTypes)
                    deviceSignature = generateDeviceSignature(deviceCert)
                    deviceSignature_str = base64.b64encode(deviceSignature).decode()
                    regData = {"DID": data[0], "DK": data[1], "deviceSignature_str": deviceSignature_str}
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
                            ciphertextData[DataID] = encryptData(Data, schoolEncKey)
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
                            plaintextData[DataID] = decryptData(Data, schoolEncKey)
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
    schoolEncKey: bytes
    
    while True:
        print("\nSign Up: Initialise user")
        input("Press Enter to start initialisation: ")
        name = "Administrator"
        print(f"Device name: {name}")
        dk, unused, keyproduct = selfKeyDev()

        #School certificate
        schoolPrivateKey = dsa.generate_private_key(key_size=2048)
        schoolCert = schoolPrivateKey.public_key()
        schoolCert_bytes = schoolCert.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        schoolCert_str = base64.b64encode(schoolCert_bytes).decode()

        #Administrator device certificate
        devicePrivateKey = dsa.generate_private_key(key_size=2048)
        deviceCert = devicePrivateKey.public_key()
        deviceSignature = generateDeviceSignature(deviceCert)

        #Registration with server
        init = requests.post(
            f"{SERVER}/init", 
            json={"name": name, "unused": unused, "schoolCert_str": schoolCert_str}
        ).json()
        uid, did = init["UID"], init["DID"]

        #Obtaining school encryption key
        try:
            loc = requests.post(
                f"{SERVER}/device_location",
                json={"uid": 1, "did": 1}
            )
            loc.raise_for_status()
        except requests.exceptions.HTTPError as e:
            print("Could not find server administrator:", e.response.json()["detail"])
            sys.exit(1)
        referral_info = loc.json()
        referral_ip = referral_info["ip"]
        referral_port = referral_info["port"]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"Connecting to server administrator at {referral_ip}:{referral_port} to obtain school encryption key...")
            s.connect((referral_ip, referral_port))
            data = json.dumps({"deviceMsg": "Obtain school encryption key", "UID": uid, "DID":did}).encode()
            s.sendall(data)
            print("Connected, awaiting response...")
            schoolEncKey_int = int(json.loads(s.recv(4096).decode()))
            schoolEncKey = schoolEncKey_int.to_bytes(32, "big")

        print(f"User registration completed for UID {uid}.")
        print(f"User Administrator initialised with UID {uid}, DID {did}, School Encryption Key {schoolEncKey}.")

        return uid, did, dk, keyproduct, schoolEncKey, devicePrivateKey, deviceCert, deviceSignature, schoolPrivateKey, schoolCert

p = requests.get(f"{SERVER}/config").json()["p"]
primeList = primes.upto(104729) # pyright: ignore[reportUnknownMemberType]

def runUserAdmin():
    start_state = load_state()
    if start_state:
        uid = start_state["UID"]
        did = start_state["DID"]
        dk = start_state["DK"]
        keyproduct = start_state["keyProduct"]
        deviceprivatekey = start_state["devicePrivateKey"]
        devicecert = start_state["deviceCert"]
        devicesignature = start_state["deviceSignature"]
        schoolenckey = start_state["schoolEncKey"]
        schoolprivatekey = start_state["schoolPrivateKey"]
        schoolcert = start_state["schoolCert"]
        print("Saved state loaded.")
    else:
        print("Fresh state loaded.")
        uid, did, dk, keyproduct, deviceprivatekey, devicecert, devicesignature, schoolenckey, schoolprivatekey, schoolcert = init_reg()
        state["UID"] = uid
        state["DID"] = did
        state["DK"] = dk
        state["keyProduct"] = keyproduct
        state["schoolEncKey"] = schoolenckey
        state["schoolPrivateKey"] = schoolprivatekey
        state["schoolCert"] = schoolcert
        save_state(state)
    return uid, did, dk, keyproduct, deviceprivatekey, devicecert, devicesignature, schoolenckey, schoolprivatekey, schoolcert

def revoke_device(uid: int, did: int, deviceprivatekey: dsa.DSAPrivateKey, devicecert: dsa.DSAPublicKey, devicesignature: bytes):
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
    did_selection = int(input("Select DID to revoke: "))-1
    revoke_did = int(did_list[did_selection])
    message_str = f"Revoke{revoke_did}"
    message_bytes = base64.b64decode(message_str.encode())
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
    print(revocation["result"])

UID, DID, DK, keyProduct, devicePrivateKey, deviceCert, deviceSignature, schoolEncKey, schoolPrivateKey, schoolCert = runUserAdmin()

#start listener
listener_thread = threading.Thread(target=inbound_socket, args=(UID, DID, keyProduct), daemon=False)
listener_thread.start()

while True:
    input("Press enter to revoke devices. Else, listening...")
    revoke_device(UID, DID, devicePrivateKey, deviceCert, deviceSignature)