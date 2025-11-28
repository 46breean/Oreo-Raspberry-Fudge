import sys, random, requests, ast, json

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

def handle_registration(uid: int, did: int, keyproduct:list[int], addr:str, tmp_path:str):
    print(f"Incoming registration request from {addr}")
    print("Type '1' to accept request, type anything else to reject request.")
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
        new_did:int = register_data["new_did"]
        data = [new_did, new_dk]

    else:
        data = b"REJECTED"

    with open(tmp_path, "w") as f:
        json.dump(data, f)

    input("\nPress Enter to continue...")

uid, did, addr, keyproduct, tmp_path = sys.argv[1:]
uid = int(uid)
did = int(did)
keyproduct = ast.literal_eval(keyproduct)

handle_registration(uid, did, keyproduct, addr, tmp_path)