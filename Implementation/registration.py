import sys, random, requests, ast, json

SERVER = "http://:8000"

def keyDev(keyproduct):
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

    return base, unused

def handle_registration(UID, DID, newdev_ms, keyproduct, addr, tmp_path):
    print(f"[Device {DID}] Incoming registration request from {addr}")
    print("\nRegistration Request:", newdev_ms)
    print("1. Accept Request")
    print("2. Reject Request")

    regreq_ans = int(input("Would you like to register this device? "))

    if regreq_ans == 1:

        while True:
            new_dk, unused = keyDev(keyproduct)
            register = requests.post(
                f"{SERVER}/register",
                json={"uid": UID, "did": DID, "unused": unused}
            )

            if register.status_code == 409:
                print("DK invalid, retrying...")
                continue

            try:
                register.raise_for_status()
                register_data = register.json()
                break
            except requests.exceptions.HTTPError as e:
                try:
                    # Try to extract JSON error detail
                    err_detail = e.response.json().get("detail", str(e))
                except ValueError:
                    # If response is not JSON
                    err_detail = e.response.text or str(e)
                print("Registration failed:", err_detail)
                continue  # try again or break depending on your logic

        new_did = register_data["new_did"]
        
        data = [new_did, new_dk, unused]

    elif regreq_ans == 2:
        data = b"REJECTED"

    with open(tmp_path, "w") as f:
        json.dump(data, f)

    input("\nPress Enter to continue...")


UID, DID, addr, newdev_ms, keyproduct, tmp_path = sys.argv[1:]
UID = int(UID)
DID = int(DID)
keyproduct = ast.literal_eval(keyproduct)

handle_registration(UID, DID, newdev_ms, keyproduct, addr, tmp_path)