from primePy import primes # pyright: ignore[reportMissingTypeStubs]
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.exceptions import InvalidSignature
from typing import cast
import requests, random, math, hashlib, socket, sys, threading, json, base64, os, subprocess, tempfile, time

SERVER = "http://127.0.0.1:8000"

devices: dict[int, str] = {}
cert_dict: dict[int, bytes] = {}
certificate_revocationlist: list[bytes] = []

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

def generateDeviceSignature(devicecert: dsa.DSAPublicKey, schoolprivatekey:dsa.DSAPrivateKey):
    deviceCert_bytes = devicecert.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    devicesignature = schoolprivatekey.sign(deviceCert_bytes, hashes.SHA256())
    return devicesignature

def encryptData(data:str, schoolenckey:bytes) -> str:
    aes = AESGCMSIV(schoolenckey)
    nonce = b"\x00"*12
    plaintext = data.encode("utf-8")
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

def inbound_socket(uid:int, did:int, keyproduct:list[int], schoolcert:dsa.DSAPublicKey, schoolprivatekey:dsa.DSAPrivateKey, schoolenckey:bytes):
    regData: dict[str,int|str]
    
    HOST = get_local_ip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        s.listen()
        PORT = s.getsockname()[-1]
        requests.post(
            f"{SERVER}/announce", 
            json={"uid": uid, "did": did, "ip": HOST, "port": PORT}
        ).json()

        while True:
            conn, _ = s.accept()
            with conn:
                data = json.loads(conn.recv(4096).decode())
                deviceMsg: str = data["deviceMsg"]

                if deviceMsg == "Register New Device":
                    deviceName: str = data["deviceName"]

                    if deviceName in devices.values():
                        conn.sendall(b"Invalid name")
                        continue

                    print(f"\n\nIncoming registration request from {deviceName}")

                    deviceCert_str: str = data["deviceCert"]
                    tmp = tempfile.NamedTemporaryFile(delete=False)
                    tmp_path = tmp.name
                    tmp.close()

                    subprocess.Popen([
                        "start", "cmd", "/c",
                        sys.executable, "devregistration.exe",
                        str(uid), str(did),
                        str(deviceName),
                        str(keyproduct), str(tmp_path)
                    ], shell=True)

                    while not os.path.exists(tmp_path) or os.path.getsize(tmp_path) == 0:
                        time.sleep(0.2)
                    with open(tmp_path, "r") as f:
                        data = json.load(f)
                    os.remove(tmp_path)

                    if isinstance(data, str) and data == "REJECTED":
                        conn.sendall(b"REJECTED")
                        print("\nDevice registration rejected by admin.")
                        continue

                    deviceCert_bytes = base64.b64decode(deviceCert_str.encode())

                    cert_dict[did] = deviceCert_bytes

                    deviceCert_publicKeyTypes = serialization.load_pem_public_key(deviceCert_bytes)
                    devicecert = cast(dsa.DSAPublicKey, deviceCert_publicKeyTypes)
                    deviceSignature = generateDeviceSignature(devicecert, schoolprivatekey)
                    deviceSignature_str = base64.b64encode(deviceSignature).decode()
                    
                    device_did: int = int(data[0])

                    regData = {"DID": device_did, "DK": data[1], "deviceSignature_str": deviceSignature_str}

                    devices[device_did] = deviceName

                    conn.sendall(json.dumps(regData).encode())
                    print(f"Device registration for DID {device_did} completed.")
                    print("\nUser Administrator Menu:")
                    print("1. Revoke device.")
                    print("2. Request for school encryption key.")
                    print("Select function: ")
                
                elif deviceMsg == "Encrypt Data":
                    # retrieving DID and SData
                    device_did = data["DID"]
                    plaintextdata: dict[str, str] = data["StudentData"]

                    print(f"\n\nIncoming encryption request from Device {device_did}.")

                    # verifying device
                    deviceCert_str: str = data["deviceCert_str"]
                    msgSignature_str: str = data["msgSignature_str"]
                    devicesignature_str: str = data["deviceSignature_str"]

                    deviceCert_bytes = base64.b64decode(deviceCert_str.encode())

                    if deviceCert_bytes in certificate_revocationlist:
                        print("Device has been revoked. Encryption unauthorised.")
                        print("\nUser Administrator Menu:")
                        print("1. Revoke device.")
                        print("2. Request for school encryption key.")
                        print("Select function: ")
                        conn.sendall(b"REJECTED")
                        continue                        

                    deviceCert_publicKeyTypes = serialization.load_pem_public_key(deviceCert_bytes)
                    deviceCert_DSAPublicKey = cast(dsa.DSAPublicKey, deviceCert_publicKeyTypes)
                    deviceSignature_bytes = base64.b64decode(devicesignature_str.encode())

                    try:
                        schoolcert.verify(deviceSignature_bytes, deviceCert_bytes, hashes.SHA256())
                    except InvalidSignature:
                        print("Device certificate is invalid. Encryption unauthorised.")
                        print("\nUser Administrator Menu:")
                        print("1. Revoke device.")
                        print("2. Request for school encryption key.")
                        print("Select function: ")
                        conn.sendall(b"REJECTED")
                        continue                        
                    
                    msgSignature_bytes = base64.b64decode(msgSignature_str.encode())
                    message_bytes = deviceMsg.encode()

                    try:
                        deviceCert_DSAPublicKey.verify(msgSignature_bytes, message_bytes, hashes.SHA256())
                    except InvalidSignature:
                        conn.sendall(b"REJECTED")
                        continue

                    # encrypting data
                    ciphertextdata = {}
                    for DataID, Data in plaintextdata.items():
                        ciphertextdata[DataID] = encryptData(Data, schoolenckey)
                    print(f"\n[Device {device_did}] Encryption successful.")
                    print("\nUser Administrator Menu:")
                    print("1. Revoke device.")
                    print("2. Request for school encryption key.")
                    print("Select function: ")

                    conn.sendall(json.dumps(ciphertextdata).encode())
                
                elif deviceMsg == "Decrypt Data":
                    # retrieving DID and SData
                    device_did = data["DID"]
                    ciphertextData: dict[str, str] = data["StudentData"]

                    print(f"\n\nIncoming decryption request from Device {device_did}.")

                    # verifying device
                    deviceCert_str: str = data["deviceCert_str"]                    
                    msgSignature_str: str = data["msgSignature_str"]
                    devicesignature_str: str = data["deviceSignature_str"]

                    deviceCert_bytes = base64.b64decode(deviceCert_str.encode())

                    if deviceCert_bytes in certificate_revocationlist:
                        conn.sendall(b"REJECTED")
                        print("Device certificate is invalid. Decryption unauthorised.")
                        print("\nUser Administrator Menu:")
                        print("1. Revoke device.")
                        print("2. Request for school encryption key.")
                        print("Select function: ")
                        continue

                    deviceCert_publicKeyTypes = serialization.load_pem_public_key(deviceCert_bytes)
                    deviceCert_DSAPublicKey = cast(dsa.DSAPublicKey, deviceCert_publicKeyTypes)
                    deviceSignature_bytes = base64.b64decode(devicesignature_str.encode())

                    try:
                        schoolcert.verify(deviceSignature_bytes, deviceCert_bytes, hashes.SHA256())
                    except InvalidSignature:
                        print("Device certificate is invalid. Decryption unauthorised.")
                        print("\nUser Administrator Menu:")
                        print("1. Revoke device.")
                        print("2. Request for school encryption key.")
                        print("Select function: ")
                        conn.sendall(b"REJECTED")
                        continue  
                    
                    signature_bytes = base64.b64decode(msgSignature_str.encode())
                    message_bytes = deviceMsg.encode()

                    try:
                        deviceCert_DSAPublicKey.verify(signature_bytes, message_bytes, hashes.SHA256())
                    except InvalidSignature:
                        conn.sendall(b"REJECTED")
                        print("\nUser Administrator Menu:")
                        print("1. Revoke device.")
                        print("2. Request for school encryption key.")
                        print("Select function: ")
                        continue

                    #decrypting data
                    plaintextData = {}
                    for DataID, Data in ciphertextData.items():
                        plaintextData[DataID] = decryptData(Data, schoolenckey)

                    print(f"\n[Device {device_did}] Decryption successful")
                    print("\nUser Administrator Menu:")
                    print("1. Revoke device.")
                    print("2. Request for school encryption key.")
                    print("Select function: ")
                    
                    conn.sendall(json.dumps(plaintextData).encode())
                
                else:
                    print("This functionality has not yet been programmed for.")

def initialisation():
    uid: int
    did: int
    dk: int
    keyproduct: list[int]
    schoolenckey: bytes
    
    while True:
        print("\n====== Initialise user ======")
        name = str(input("Input username: "))
        otp = str(input("Input OTP for initialisation: "))

        while True:

            uid = random.randint(10**9, 10**10 - 1)

            idcheck = requests.get(
                f"{SERVER}/id_check",
                params={"uid": uid}
            )

            idcheck = idcheck.json()

            if idcheck == "invalid UID":
                continue
            else:
                break
        
        did = random.randint(10**9, 10**10 - 1)


        dk, unused, keyproduct = selfKeyDev()

        #School certificate
        schoolprivatekey = dsa.generate_private_key(key_size=2048)
        schoolcert = schoolprivatekey.public_key()
        schoolcert_bytes = schoolcert.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        schoolcert_str = base64.b64encode(schoolcert_bytes).decode()

        try:
            loc = requests.get(
                f"{SERVER}/device_location",
                params={"uid": 1, "did": 1}
            )
            loc.raise_for_status()
        except requests.exceptions.HTTPError as e:
            print("Could not find server administrator:", e.response.json()["detail"])
            sys.exit(1)
        referral_info = loc.json()
        referral_ip = referral_info["ip"]
        referral_port = referral_info["port"]

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"\nConnecting to server administrator at {referral_ip}:{referral_port} to obtain school encryption key...")
            s.connect((referral_ip, referral_port))
            data = json.dumps({"Username": name, "OTP": otp, "schoolCert": schoolcert_str, "deviceMsg": "Initialisation request", "UID": uid, "DID":did}).encode()
            s.sendall(data)
            print("Connected, awaiting response...")

            raw = s.recv(4096)
            if not raw:
                print("Server closed connection unexpectedly")
                sys.exit(1)

            response = json.loads(raw.decode())
            if response == "REJECTED":
                print("\nIncorrect OTP. Initialisation failed.")
                sys.exit(1)
            else:
                print("\nCorrect OTP. Beginning initialisation...")
                schoolenckey_int = int(response)
                schoolenckey = schoolenckey_int.to_bytes(32, "big")

        #Registration with server
        requests.post(
            f"{SERVER}/init", 
            json={"name": name, "unused": unused, "schoolCert_str": schoolcert_str, "uid": uid, "did":did}
        ).json()        

        print(f"\nUser Administrator of {name} initialised with UID {uid}, DID {did}, school encryption key.")


        return uid, did, dk, keyproduct, schoolenckey, schoolprivatekey, schoolcert, referral_ip, referral_port, name

def revoke_device(uid: int, did: int, schoolprivatekey: dsa.DSAPrivateKey):
    try:
        revoke_list = requests.get(
            f"{SERVER}/revoke_list",
            params = {"uid": uid, "did": did}
        )
        revoke_list.raise_for_status()
        did_list: list[int] = revoke_list.json()["dids"]
    except requests.exceptions.HTTPError as e:
        print ("Revocation failed:", e.response.json()["detail"])
        sys.exit(1)

    revokeNames: list[str] = []

    for d in did_list:
        revokeNames.append(devices[d])
    
    print(f"DIDs of registered, not yet revoked devices: {revokeNames}")
    revoke_str = str(input("Select device to revoke: "))

    revoke_did = 0

    for key, value in devices.items():
        if value == revoke_str:
            revoke_did = key

    if revoke_did == 0:
        print("This device does not exist. Please try again.")
        return
    
    message_str = f"Revoke {revoke_did}"
    message_bytes = message_str.encode()
    msgSignature = schoolprivatekey.sign(message_bytes, hashes.SHA256())
    msgSignature_str = base64.b64encode(msgSignature).decode()
    revocation = requests.post(
        f"{SERVER}/revoke",
        json={"uid": uid, "did": did, "revoke_did": revoke_did, "message_str": message_str, "msgSignature_str": msgSignature_str}
    ).json()
    
    print(f"{revocation["result"]} for {revoke_str}.")

    deviceCert_bytes = cert_dict[did]
    certificate_revocationlist.append(deviceCert_bytes)

    # uid: int
    # did: int
    # revoke_did: int
    # message_str: str
    # msgSignature_str: str
    # deviceCert_str: str
    # deviceSignature_str: str

p = requests.get(f"{SERVER}/config").json()["p"]
primeList = primes.upto(104729) # pyright: ignore[reportUnknownMemberType]

def runUserAdmin():
    uid, did, dk, keyproduct, schoolenckey,schoolprivatekey, schoolcert, referral_IP, referral_PORT, name = initialisation()
    return uid, did, dk, keyproduct, schoolenckey, schoolprivatekey, schoolcert, referral_IP, referral_PORT, name

UID, DID, DK, keyProduct, schoolEncKey, schoolPrivateKey, schoolCert, referral_IP, referral_PORT, name = runUserAdmin()

#start listener
stop_event = threading.Event()

listener_thread = threading.Thread(target=inbound_socket, args=(UID, DID, keyProduct, schoolCert, schoolPrivateKey, schoolEncKey), daemon=True)
listener_thread.start()

while True:
    print("\nUser Administrator Menu:")
    print("1. Revoke device.")
    print("2. Request for school encryption key.")
    choice = input("Select function: ")

    try:
        choice = int(choice)
        if choice == 1:
            revoke_device(UID, DID, schoolPrivateKey)
        elif choice == 2:
            message_str = f"Obtain school encryption key request"
            message_bytes = message_str.encode()
            msgSignature = schoolPrivateKey.sign(message_bytes, hashes.SHA256())
            msgSignature_str = base64.b64encode(msgSignature).decode()
        
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

                print(f"\nConnecting to server administrator at {referral_IP}:{referral_PORT} to obtain school encryption key...")
                s.connect((referral_IP, referral_PORT))
                data = json.dumps({"Username": name, "deviceMsg": "Obtain school encryption key", "UID": UID, "DID":DID, "message_str": message_str, "msgSignature_str": msgSignature_str}).encode()
                s.sendall(data)
                print("Connected, awaiting response...")

                raw = s.recv(4096)
                if not raw:
                    print("Server administrator closed connection unexpectedly")
                    continue

                response = json.loads(raw.decode())
                if response == "REJECTED":
                    print("\nRequest to obtain school encryption key rejected.")
                    continue
                else:
                    schoolenckey_int = int(response)
                    schoolEncKey = schoolenckey_int.to_bytes(32, "big")
                    print("\nRequest accepted. School key regenerated.")
        else:
            print("Please select a valid function.")

    except ValueError:
        print("Invalid input")