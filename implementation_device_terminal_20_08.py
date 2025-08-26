import requests, random, hashlib, math
from primePy import primes
import sympy

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
        for i in range(100):
            pick = random.choice(primeList)
            base *= pick
        return base

DK = keyDev()

factors = sympy.divisors(DK)

init = requests.post(f"{SERVER}/init").json()
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
            factor = random.choice(factors)
            register = requests.post(
                f"{SERVER}/register",
                json={"uid": UID, "did": DID, "factor": factor}
            ).json()
            print("Registered:", register)
        elif choice == 2:
            revoke_list = requests.get(
                f"{SERVER}/revoke_list",
                params = {"uid": UID, "did": DID}
            ).json()
            print(f"DIDs of registered, not yet revoked devices: {revoke_list}")

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
            resp1 = requests.post(f"{SERVER}/eval/step1", json={"uid": UID, "did": DID, "blinded": blinded}).json()
            blinded2 = resp1["blinded2"]

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