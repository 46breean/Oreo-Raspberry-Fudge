from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import base64, sys, ast, json

SERVER = "http://172.22.13.14:8000"

def encryptData(data:str, schoolenckey:bytes) -> str:
    aes = AESGCMSIV(schoolenckey)
    nonce = b"\x00"*12
    plaintext = data.encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return base64.b64encode(ciphertext).decode()

def handle_encryption(did:int, plaintextdata:dict[str, str], schoolenckey:bytes, tmp_path:str):

    print(f"Incoming data encryption request from (device name) (DID {did}).")
    regreq_ans = int(input("Type 1 to accept request, type any other key to reject request: "))
    if regreq_ans == 1:
        ciphertextdata = {}
        for DataID, Data in plaintextdata.items():
            ciphertextdata[DataID] = encryptData(Data, schoolenckey)
    else:
        ciphertextdata = b"REJECTED"

    with open(tmp_path, "w") as f:
        json.dump(ciphertextdata, f)

    input("\nPress Enter to continue...")

did, tmp_path, schoolEncKey, plaintextData = sys.argv[1:]
did = int(did)
plaintextData = ast.literal_eval(plaintextData)
schoolEncKey = ast.literal_eval(schoolEncKey)

handle_encryption(did, plaintextData, schoolEncKey, tmp_path)