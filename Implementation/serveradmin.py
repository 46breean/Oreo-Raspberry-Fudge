from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import hashlib, socket, json, requests, threading, os, pickle

SERVER = "http://172.22.13.14:8000"

state: dict[str, bytes|int] = {}

def save_state(state: dict[str, bytes|int], filename:str ='serveradmin_state.pk1'):
    with open(filename, "wb") as f:
        pickle.dump(state, f)

def load_state(filename:str = 'serveradmin_state.pk1'):
    if not os.path.exists(filename):
        return None
    with open(filename, "rb") as f:
        return pickle.load(f)

def masterKeyDev() -> bytes:
    masterKey = AESGCMSIV.generate_key(bit_length=256)
    return masterKey

def schoolKeyDev(masterKey:bytes, uid:int, did:int) -> bytes:
    salt = hashlib.sha256(f"{uid}{did}".encode()).digest()
    schoolKey = HKDF(algorithm = hashes.SHA256(), length = 32, salt = salt, info = b"").derive(masterKey)
    return schoolKey

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def revoke_user():
    uid:str = input("Enter UID that is to be revoked: ")
    revoke = requests.post(
        f"{SERVER}/super_revoke", 
        json={"uid": uid}
    ).json()
    print(revoke["result"])

def inbound_socket(uid: int, did: int, masterKey: bytes):
    host = get_local_ip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        s.listen()
        port = s.getsockname()[-1]
        resp = requests.post(
            f"{SERVER}/announce", 
            json={"uid": uid, "did": did, "ip": host, "port": port}
        ).json()
        print(resp["result"])
        print(f"Listener started on {host}:{port}...")
        while True:
            conn = s.accept()[0] #addr unused
            with conn:
                data = json.loads(conn.recv(4096).decode())
                deviceMsg, uid, did = data["deviceMsg"], data["UID"], data["DID"]
                if deviceMsg == "Obtain school encryption key":
                    schoolKey_bytes = schoolKeyDev(masterKey, uid, did)
                    schoolKey = int.from_bytes(schoolKey_bytes, "big")
                    data_to_send = json.dumps(schoolKey)
                    conn.sendall(data_to_send.encode())
                    print(f"[User {uid}] User initialisation completed.")
                else:
                    print("This functionality has not yet been programmed for.")

def init_reg() -> tuple[int, int]:
    init = requests.post(
        f"{SERVER}/super_init", 
        json={"name": "serverAdmin"}
    ).json()
    uid, did = init["UID"], init["DID"]
    print(f"Server Administrator initialised with UID {uid}, DID {did}")
    return uid, did

def runServerAdmin():
    start_state = load_state()
    if start_state:
        masterKey = start_state["masterKey"]
        uid = start_state["UID"]
        did = start_state["DID"]
        print("Saved state loaded.")
    else:
        print("Fresh state loaded.")
        masterKey = masterKeyDev()
        uid, did = init_reg()
        state["masterKey"] = masterKey
        state["UID"] = uid
        state["DID"] = did
        save_state(state)
    return uid, did, masterKey

UID, DID, masterKey = runServerAdmin()

#start listener
listener_thread = threading.Thread(target=inbound_socket, args=(UID, DID, masterKey), daemon=False)
listener_thread.start()

while True:
    input("Press enter to revoke devices. Else, listening...")
    revoke_user()