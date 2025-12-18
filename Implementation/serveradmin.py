import socket, json, requests, random, threading, base64, hashlib
from typing import cast
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.exceptions import InvalidSignature

SERVER = "http://172.22.13.14:8000"
active_otps: dict[str, int|None] = {}
unrevoked_uids: dict[str, int|None] = {} # name : uid
school_certs: dict[int, dsa.DSAPublicKey|None] = {} # uid : cert

def masterEncKeyDev() -> bytes:
    return AESGCMSIV.generate_key(bit_length=256)

def schoolEncKeyDev(masterEncKey: bytes, uid: int, did: int) -> bytes:
    salt = hashlib.sha256(f"{uid}{did}".encode()).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"").derive(masterEncKey)

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def revoke_user(serveradminprivatekey: dsa.DSAPrivateKey):
    names = [name for (name), uid in unrevoked_uids.items() if uid is not None]
    print("\nList of unrevoked users:")
    print(names)
    username = input("Enter user to be revoked: ")

    try:
        revoke_uid = unrevoked_uids[username]
    except KeyError:
        print("User does not exist or has been revoked.")
        return

    if revoke_uid is None:
        print("User has been revoked.")
        return
    
    message_str = f"Revoke {revoke_uid}"
    message_bytes = message_str.encode()
    msgSignature = serveradminprivatekey.sign(message_bytes, hashes.SHA256())
    msgSignature_str = base64.b64encode(msgSignature).decode()

    revoke = requests.post(
        f"{SERVER}/super_revoke", json={"uid": revoke_uid, "message_str": message_str, "msgSignature_str": msgSignature_str}
    ).json()
    print(revoke.get("result", "No response"))

    school_certs[revoke_uid] = None
    unrevoked_uids[username] = None

def handle_user_connection(conn: socket.socket, masterEncKey: bytes):
    with conn:
        try:
            data = json.loads(conn.recv(4096).decode())
        except json.JSONDecodeError:
            print("Received invalid JSON from user, rejecting...")
            conn.sendall(json.dumps("REJECTED").encode())
            return

        try:
            if data["deviceMsg"] == "Initialisation request":
                username = str(data["Username"])
                userotp = int(data["OTP"])
                print(f"\n\nReceived initialisation request from {username}.")

                if username not in active_otps:
                    conn.sendall(json.dumps("REJECTED").encode())
                    print(f"Username invalid. Request rejected.")
                    return
                elif active_otps[username] == None:
                    conn.sendall(json.dumps("REJECTED").encode())
                    print("User has already been initialised.")
                    print("\nServer Administrator Menu:")
                    print("1. Initialise new user.")
                    print("2. Revoke user.")
                    print("Select function: ")
                    return
                elif userotp != active_otps[username]:
                    conn.sendall(json.dumps("REJECTED").encode())
                    print(f"Incorrect OTP from {username}. Request rejected.")
                    return
                elif userotp == active_otps[username]:
                    print(f"Correct OTP. Initialising {username}...")

                    active_otps[username] = None
                    uid, did = data["UID"], data["DID"]
                    schoolEncKey_bytes = schoolEncKeyDev(masterEncKey, uid, did)
                    schoolEncKey = int.from_bytes(schoolEncKey_bytes, "big")
                    conn.sendall(json.dumps(schoolEncKey).encode())

                    print(f"[{uid} {username}] Initialised successfully.")
                    unrevoked_uids[username] = uid
                    
                    schoolcert_str: str = data["schoolCert"]
                    schoolcert_bytes = base64.b64decode(schoolcert_str.encode())
                    schoolcert_publicKeyTypes = serialization.load_pem_public_key(schoolcert_bytes)
                    schoolcert = cast(dsa.DSAPublicKey, schoolcert_publicKeyTypes)
                    school_certs[uid] = schoolcert

                    print("\nServer Administrator Menu:")
                    print("1. Initialise new user.")
                    print("2. Revoke user.")
                    print("Select function: ")
            
            elif data["deviceMsg"] == "Obtain school encryption key":
                name = data["Username"]

                print(f"\n\nRecevied request to obtain school encryption key from {name}.")
                uid: int = data["UID"]
                did: int = data["DID"]
                message_str: str = data["message_str"]
                msgSignature_str: str = data["msgSignature_str"]
                schoolCert = school_certs[uid]

                if schoolCert is None:
                    print("School has been revoked.")
                    conn.sendall(json.dumps("REJECTED").encode())
                    return
                
                message_bytes = message_str.encode()
                msgSignature_bytes = base64.b64decode(msgSignature_str.encode())

                try:
                    schoolCert.verify(msgSignature_bytes, message_bytes, hashes.SHA256())
                except InvalidSignature:
                    print("Signature is invalid. Request unauthorised.")
                    conn.sendall(json.dumps("REJECTED").encode())
                    return
                
                schoolEncKey_bytes = schoolEncKeyDev(masterEncKey, uid, did)
                schoolEncKey = int.from_bytes(schoolEncKey_bytes, "big")
                conn.sendall(json.dumps(schoolEncKey).encode())

                print("\nServer Administrator Menu:")
                print("1. Initialise new user.")
                print("2. Revoke user.")
                print("Select function: ")

        except Exception as e:
            print(f"Error handling connnection: {e}")

def user_listener(uid: int, did: int, masterEncKey: bytes):
    host = get_local_ip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        s.listen()
        port = s.getsockname()[-1]

        # Announce listener to server
        requests.post(f"{SERVER}/announce", json={"uid": uid, "did": did, "ip": host, "port": port})
        while True:
            conn, _ = s.accept()
            threading.Thread(target=handle_user_connection, args=(conn, masterEncKey), daemon=True).start()

def initialisation(serveradmincert_str: str) -> tuple[int, int, bytes]:
    init = requests.post(f"{SERVER}/super_init", json={"name": "serverAdmin", "servadminCert": serveradmincert_str}).json()
    uid, did = init["UID"], init["DID"]
    masterenckey = masterEncKeyDev()
    print(f"Server Administrator initialised with UID {uid}, DID {did}")
    return uid, did, masterenckey

def runServerAdmin():
    serveradminprivatekey = dsa.generate_private_key(key_size=2048)
    serveradmincert = serveradminprivatekey.public_key()
    serveradmincert_bytes = serveradmincert.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    serveradmincert_str = base64.b64encode(serveradmincert_bytes).decode()
    uid, did, masterenckey = initialisation(serveradmincert_str)
    return uid, did, masterenckey, serveradminprivatekey

# ----------------- MAIN -----------------
UID, DID, masterEncKey, serveradminPrivateKey = runServerAdmin()

# Start listener thread once
listener_thread = threading.Thread(target=user_listener, args=(UID, DID, masterEncKey), daemon=True)
listener_thread.start()

while True:
    print("\nServer Administrator Menu:")
    print("1. Initialise new user.")
    print("2. Revoke user.")
    choice = input("Select function: ")

    try:
        choice = int(choice)
        if choice == 1:
            username = str(input("\nEnter new username: "))
            if username in active_otps.keys():
                print("Username taken. Please choose another username.")
                continue
            otp = random.randint(10**7, 10**8 - 1)
            active_otps[username] = otp
            print(f"\nInitialising new user. \n Username: {username} \n OTP: {otp}")
        elif choice == 2:
            revoke_user(serveradminPrivateKey)
        else:
            print("Please select a valid function.")
    except ValueError:
        print("Invalid input")