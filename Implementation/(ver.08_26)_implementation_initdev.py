import requests, random, hashlib, math
from primePy import primes
import sympy
import subprocess
import sys

SERVER = "http://127.0.0.1:8000"

def hash_int(x: int) -> int:
    m = hashlib.sha256()
    m.update(str(x).encode())
    return int(m.hexdigest(), 16)

def random_coprime(p_minus_1: int) -> int:
    while True:
        r = random.randint(2, p_minus_1)
        if math.gcd(r, p_minus_1) == 1:
            return r

p = requests.get(f"{SERVER}/config").json()["p"]

primeList = primes.upto(104729)

def keyDev():
    base = 1
    for i in range(5):
        pick = random.choice(primeList)
        base *= pick
    return base

DK = keyDev()

factors = sympy.divisors(DK)

name = input("Enter device name: ")
init = requests.post(f"{SERVER}/init", params={"name": name}).json()
UID, DID = init["UID"], init["DID"]
print("Initialised:", init)

def fn_selection():
    while True:
        print("\nDevice Menu:")
        print("1. Register with server")
        print("2. Revoke device")
        print("3. Evaluate")
        print("4. Exit")
        choice = int(input("Select function: "))

        if choice == 1:
            while True:
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

            new_did = register_data["new_did"]
            new_dk = DK//factor
            subprocess.Popen(
                ["python", "implementation_regdev.py", str(UID), str(new_did), str(new_dk)],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            print("Registered:", register_data)
        elif choice == 2:
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
        elif choice == 3:
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
        elif choice == 4:
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")

fn_selection()