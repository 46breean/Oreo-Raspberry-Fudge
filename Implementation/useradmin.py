import requests, random, math, hashlib, socket, sys, threading, time, subprocess, tempfile, os, json, ast
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
                    sys.executable, "registration.py",
                    str(UID), str(DID),
                    addr[0],
                    str(addr[1]),
                    newdev_msg,
                    str(keyproduct),
                    tmp_path
                ])

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
        print("\nSign Up: Initialise user")
        name = "admin"
        print(f"Device name: {name}")
        dk, unused, keyproduct = keyDev()
        init = requests.post(f"{SERVER}/init", json={"name": name, "unused": unused}).json()
        uid, did = init["UID"], init["DID"] 
        print (f"Admin device initialised with UID: {uid}, admin DID: {did}")

        return uid, did, dk, keyproduct

p = requests.get(f"{SERVER}/config").json()["p"]
primeList = primes.upto(104729)

UID, DID, DK, keyProduct = init_reg()

#start listener
listener_thread = threading.Thread(target=inbound_socket, args=(UID, DID, keyProduct), daemon=False)
listener_thread.start()