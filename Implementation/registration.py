import sys, random, requests, socket, ast

SERVER = "http://127.0.0.1:8000"

def handle_registration(UID, DID, DK, newdev_ms, factors, control_port, addr):
    print(f"[Device {DID}] Incoming registration request from {addr}")
    print("\nRegistration Request:", newdev_ms)
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
                return
            register.raise_for_status()
            register_data = register.json()
        except requests.exceptions.HTTPError as e:
            print(e.response.json()["detail"])
            return

        new_did = register_data["new_did"]
        new_dk = DK // factor
        data = f"{new_did},{new_dk}"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", control_port))
            s.sendall(data.encode())

    elif regreq_ans == 2:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", control_port))
            s.sendall(b"REJECTED")

    input("\nPress Enter to continue...")


UID, DID, DK, addr, control_port, newdev_ms, factors = sys.argv[1:]
UID = int(UID)
DID = int(DID)
DK = int(DK)
control_port = int(control_port)
factors = ast.literal_eval(factors)

handle_registration(UID, DID, DK, newdev_ms, factors, control_port, addr)