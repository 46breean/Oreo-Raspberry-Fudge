import sys, random, requests, ast, json, os

SERVER = "http://172.22.13.14:8000"

def keyDev(keyproduct:list[int]):
    requirement = False
    bitstring = []
    while requirement == False:
        bitstring = [random.randint(0, 1) for _ in range(100)]
        if bitstring.count(1)>=50 and bitstring.count(1)<=70:
            requirement = True
    base: int = 1
    unused: int = 1

    for i in range(100):
        if bitstring[i] == 1:
            base *= keyproduct[i]
        else:
            unused *= keyproduct[i]
    return base, unused

def handle_registration(uid: int, did: int, keyproduct:list[int], devicename:str, tmp_path:str):
    print(f"Incoming registration request from {devicename}")
    print("Type '1' to register device, type anything else to reject registration.")
    regreq_ans = int(input("Would you like to register this device? "))

    if regreq_ans == 1:
        while True:
            new_dk, unused = keyDev(keyproduct)
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
                new_did:int = register_data["new_did"]
                data = [new_did, new_dk]
                break
            except requests.exceptions.HTTPError as e:
                try:
                    # extract JSON error detail
                    err_detail = e.response.json().get("detail", str(e))
                except ValueError:
                    # if response is not JSON
                    err_detail = e.response.text or str(e)
                
                data = "REJECTED"
                print("Registration failed:", err_detail)
                break

    else:
        data = "REJECTED"

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())

    print("\nRegistration decision saved. Press Enter to continue...")
    input()


if __name__ == "__main__":
    uid, did, devicename, keyproduct, tmp_path = sys.argv[1:]
    uid = int(uid)
    did = int(did)
    keyproduct = ast.literal_eval(keyproduct)

    handle_registration(uid, did, keyproduct, devicename, tmp_path)