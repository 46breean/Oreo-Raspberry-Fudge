import requests, sympy, random, math, hashlib, socket, sys
from primePy import primes

SERVER = "http://127.0.0.1:8000"

p = requests.get(f"{SERVER}/config").json()["p"]
primeList = primes.upto(104729)

def hash_int(x: int) -> int:
    m = hashlib.sha256()
    m.update(str(x).encode())
    return int(m.hexdigest(), 16)

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

def init_reg():
    while True:
        print("\nSign Up:")
        print("1. Initialise user")
        print("2. Register new device")
        choice = int(input("Select function: "))

        if choice == 1:
            # devname, generating UID, DID
            name = input("Enter device name: ")
            init = requests.post(f"{SERVER}/init", params={"name": name}).json()
            UID, DID = init["UID"], init["DID"]

            # choosing DK and factors
            DK = firstKeyDev()
            factors = sympy.divisors(DK)
            print("Initialised:", init)

            # in socket
            HOST = ''
            PORT = 49153
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((HOST, PORT))
                s.listen(1)
                conn, addr = s.accept()
                with conn:
                    while True:
                        newdev_msg = conn.recv(1024)
                        if not newdev_msg: break
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
                                break
                            except requests.exceptions.HTTPError as e:
                                print(e.response.json()["detail"])
                                input("Press Enter to continue...")
                                return
                        elif regreq_ans == 2: break

                        new_did = register_data["new_did"]
                        new_dk = DK//factor
                        data = (new_did, new_dk)
            
            return UID, DID, DK

        elif choice == 2:
            
            # retrieve DID and DK
            UID = input("Enter you UID:")
            referral_did = input("Enter the DID of your referral device:")
            HOST = str(UID) + str(referral_did)
            PORT = 49153
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                DID, DK = s.recv(1024)

            factors = sympy.divisors(DK)

            print(f"New device registered: (UID={UID}, DID={DID}, DK ={DK})")

            ## in socket
            HOST = str(UID, DID)
            PORT = 49153
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((HOST, PORT))
                s.listen(1)
                conn, addr = s.accept()
                with conn:
                    while True:
                        newdev_msg = conn.recv(1024)
                        if not newdev_msg: break
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
                                break
                            except requests.exceptions.HTTPError as e:
                                print(e.response.json()["detail"])
                                input("Press Enter to continue...")
                                return
                        elif regreq_ans == 2: break

                        new_did = register_data["new_did"]
                        new_dk = DK//factor
                        data = (new_did, new_dk)

                    conn.sendall(data)
            return UID, DID, DK

def fn_selection():

    UID, DID, DK = init_reg()["UID", "DID", "DK"]

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

init_reg()
fn_selection()
