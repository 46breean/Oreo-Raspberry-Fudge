from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import hashlib, os, sys, subprocess, socket, json, requests, threading, time

SERVER = "http://172.22.22.27:8000"
UID = 1
DID = 1

def masterKeyDev() -> bytes:
    masterKey = AESGCMSIV.generate_key(bit_length=256)
    return masterKey

def schoolKeyDev(masterKey:bytes, UID:int, DID:int) -> bytes:
    salt = hashlib.sha256(f"{UID}{DID}".encode()).digest()
    schoolKey = HKDF(algorithm = hashes.SHA256(), length = 32, salt = salt, info = b"").derive(masterKey)
    return schoolKey

def runServer() -> None:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(current_dir, "server.py")
    subprocess.Popen(f'start cmd /k "{sys.executable} {path}"', shell=True)

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def inbound_socket(UID:int, DID:int, masterKey:bytes) -> None:
    HOST = get_local_ip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        s.listen()
        PORT = s.getsockname()[-1]
        requests.post(f"{SERVER}/announce", params={"uid": UID, "did": DID, "ip": HOST, "port": PORT})
        print(f"[Server Admin] Listener started on {HOST}:{PORT}...")
        while True:
            conn = s.accept()[0] #addr unused
            with conn:
                data = json.loads(conn.recv(1024).decode())
                deviceMsg, uid, did = data["deviceMsg"], data["UID"], data["DID"]
                if deviceMsg == "Obtain school encryption key":
                    schoolKey_bytes = schoolKeyDev(masterKey, uid, did)
                    schoolKey = int.from_bytes(schoolKey_bytes, "big")
                    data_to_send = json.dumps(schoolKey)
                    conn.sendall(data_to_send.encode())
                    print(f"[User {uid}] User registration completed.")
                else:
                    print("This functionality has not yet been programmed for.")

masterKey = masterKeyDev()
runServer()
time.sleep(5)

#start listener
listener_thread = threading.Thread(target=inbound_socket, args=(UID, DID, masterKey), daemon=False)
listener_thread.start()