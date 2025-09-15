import requests, sympy, random, math, socket, sys, threading, time
from primePy import primes
from cryptography.hazmat.primitives import hashes

SERVER = "http://127.0.0.1:8000"

p = requests.get(f"{SERVER}/config").json()["p"]
primeList = primes.upto(104729)

def hash_int(x: int) -> int:
    m = hashes.Hash(hashes.SHA256())
    m.update(str(x).encode())
    return int.from_bytes(m.finalize(), byteorder="big")

def random_coprime(p_minus_1: int) -> int:
    while True:
        r = random.randint(2, p_minus_1)
        if math.gcd(r, p_minus_1) == 1:
            return r

def firstKeyDev():
    pick = []
    for i in range(100):
        pick = pick.append(random.choice(primeList))
    requirement = False
    while requirement == False:
        bitstring = [random.randint(0, 1) for n in range(100)]
        if bitstring.count(1)>=50 and bitstring.count(1)<=70:
            requirement = True
    base = 1
    unused = []
    for i in range(100):
        if bitstring[i] ==1:
            base *= pick[i]
        else:
            unused.append(pick[i])
    return base, unused

def subkeyDev(pick):
    requirement = False
    while requirement == False:
        bitstring = [random.randint(0, 1) for n in range(100)]
        if bitstring.count(1)>=50 and bitstring.count(1)<=70:
            requirement = True
    base = 1
    unused = []
    for i in range(100):
        if bitstring[i] ==1:
            base *= pick[i]
        else:
            unused.append(pick[i])
    return base, unused

def keyDev():
    base = 1
    for i in range(5):
        pick = random.choice(primeList)
        base *= pick
    return base

def get_local_ip():
    """Get the LAN IP of this device."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't have to be reachable
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def inbound_socket(UID, DID, DK, HOST, PORT):
    factors = sympy.divisors(DK)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Device {DID}] Listener started on {HOST}:{PORT}...")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[Device {DID}] Incoming registration request from {addr}")
                newdev_msg = conn.recv(1024).decode()
                if not newdev_msg:
                    continue
                print("\nRegistration Request:", newdev_msg)
                print("1. Accept Request")
                print("2. Reject Request")
                regreq_ans = int(input("Would you like to register this device? "))

                if regreq_ans == 1:
                    factor = random.choice(factors)
                    try:
                        register = requests.post(
                            f"{SERVER}/register",
                            json={"uid": UID, "did": DID, "factor": factor}
                        )
                        if register.status_code == 409:
                            print("Factor invalid, retrying...")
                            continue
                        register.raise_for_status()
                        register_data = register.json()
                    except requests.exceptions.HTTPError as e:
                        print(e.response.json()["detail"])
                        continue

                    new_did = register_data["new_did"]
                    new_dk = DK // factor
                    data = f"{new_did},{new_dk}"
                    conn.sendall(data.encode())
                    print(f"Sent new DID/DK to new device: {data}")

                elif regreq_ans == 2:
                    print("Rejected registration request")

def init_reg():
    print("\nSign Up:")
    print("1. Initialise user")
    print("2. Register new device")
    choice = int(input("Select function: "))

    if choice == 1:
        name = input("Enter device name: ")
        init = requests.post(f"{SERVER}/init", params={"name": name}).json()
        UID, DID = init["UID"], init["DID"]
        DK = keyDev()
        print("Initialised:", init)

        # announce self to server
        HOST = get_local_ip()
        PORT = 49153
        requests.post(f"{SERVER}/announce", params={"uid": UID, "did": DID, "ip": HOST, "port": PORT})

        # start listener in background
        listener_thread = threading.Thread(target=inbound_socket, args=(UID, DID, DK, HOST, PORT), daemon=True)
        listener_thread.start()
        time.sleep(0.5)  # give socket time to bind

        return UID, DID, DK

    elif choice == 2:
        UID = input("Enter your UID: ")
        referral_did = input("Enter the DID of your referral device: ")

        try:
            loc = requests.get(
                f"{SERVER}/device_location",
                params={"uid": UID, "did": referral_did}
            )
            loc.raise_for_status()
            referral_info = loc.json()
            referral_ip = referral_info["ip"]
            referral_port = referral_info["port"]
        except requests.exceptions.HTTPError as e:
            print("Could not find referral device:", e.response.json()["detail"])
            return

        # connect to referral device
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"Connecting to referral device at {referral_ip}:{referral_port}...")
            s.connect((referral_ip, referral_port))
            s.sendall(b"Registration Request")
            newdev_msg = s.recv(1024).decode()
            DID, DK = newdev_msg.split(",")
            DID, DK = int(DID), int(DK)

        # announce self to server
        HOST = get_local_ip()
        PORT = 49154
        requests.post(f"{SERVER}/announce", params={"uid": UID, "did": DID, "ip": HOST, "port": PORT})
        print(f"New device registered: (UID={UID}, DID={DID}, DK={DK})")

        # start listener
        listener_thread = threading.Thread(target=inbound_socket, args=(UID, DID, DK, HOST, PORT), daemon=True)
        listener_thread.start()
        time.sleep(0.5)

        return UID, DID, DK


def fn_selection(UID, DID, DK):

    while True:
        print("\nDevice Menu:")
        print("1. Revoke device")
        print("2. Evaluate")
        print("3. Exit")
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
            index = int(input("Enter a number to evaluate: "))
            hashed_index = hash_int(index) % p
            r1 = random_coprime(p - 1)

            blinded = pow(hashed_index, DK * r1, p)

            try:
                resp1 = requests.post(
                    f"{SERVER}/eval/step1",
                    json={"uid": UID, "did": DID, "blinded": blinded}
                )
                resp1.raise_for_status()
                blinded2 = resp1.json()["blinded2"]
            except requests.exceptions.HTTPError as e:
                print("Step 1 failed:", e.response.json()["detail"])
                input("Press Enter to continue...")
                return
            except KeyError:
                print("Unexpected response from server:", resp1.json())
                input("Press Enter to continue...")
                return

            r1_inv = pow(r1, -1, p - 1)
            unblinded1 = pow(blinded2, r1_inv, p)

            resp2 = requests.post(f"{SERVER}/eval/step2", json={"uid": UID, "did": DID, "unblinded1": unblinded1}).json()
            print("Encrypted Index:", resp2["final"])
        elif choice == 3:
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")

UID, DID, DK = init_reg()
fn_selection(UID, DID, DK)
