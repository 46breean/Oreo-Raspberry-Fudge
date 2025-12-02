import random
import math
import uvicorn
import pickle
import os
import base64
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import TypedDict, Dict, List, Tuple, Optional, cast, Union
from contextlib import asynccontextmanager
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

P = 29996224275833  # prime modulus

# database types

class UserDevice(TypedDict):
    DSK: Optional[int]
    constant: int

class UserDBEntry(TypedDict):
    cert: Optional[dsa.DSAPublicKey]
    name: str
    devices: Dict[int, UserDevice]
    studentData: Dict[int, str]
    indexData: Dict[int, List[int]]

userDB: Dict[int, UserDBEntry] = {}
device_locations: Dict[Tuple[int, int], Tuple[str, int]] = {}
r2_store: Dict[Tuple[int, int], int] = {}

STATE_FILE = "server_state.pk1"

def random_coprime(p_minus_1: int) -> int:
    while True:
        r = random.randint(2, p_minus_1)
        if math.gcd(r, p_minus_1) == 1:
            return r

def save_state(filename: str = STATE_FILE) -> None:
    with open(filename, "wb") as f:
        pickle.dump({
            "userDB": userDB,
            "device_locations": device_locations
        }, f)
    print("[STATE] Server state saved.")

def load_state(filename: str = STATE_FILE) -> None:
    if not os.path.exists(filename):
        print("[STATE] No saved state found, starting fresh.")
        return
    with open(filename, "rb") as f:
        state = pickle.load(f)
        global userDB, device_locations
        userDB = state.get("userDB", {})
        device_locations = state.get("device_locations", {})
    print("[STATE] Server state loaded.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_state()
    yield
    save_state()

app = FastAPI(title="Encrypted Indexing Server", version="1.0.0")  # , lifespan=lifespan

class AnnounceRequest(BaseModel):
    uid: int
    did: int
    ip: str
    port: int

class DeviceLocationResponse(BaseModel):
    ip: str
    port: int

class InitRequest(BaseModel):
    uid: int
    did: int
    unused: int
    name: str = Query(...)
    schoolCert_str: str

class SuperInitRequest(BaseModel):
    name: str = Query(...)

class SuperInitResponse(BaseModel):
    UID: int
    DID: int

class RegisterRequest(BaseModel):
    uid: int
    did: int
    unused: int

class RegisterResponse(BaseModel):
    new_did: int

class RevokeRequest(BaseModel):
    uid: int
    did: int
    revoke_did: int
    message_str: str
    msgSignature_str: str

class RevokeResponse(BaseModel):
    result: str

class RevokeListResponse(BaseModel):
    dids: List[int]

class SuperRevokeRequest(BaseModel):
    uid: int

class SuperRevokeResponse(BaseModel):
    result: str

class EvalStep1Request(BaseModel):
    uid: int
    did: int
    blinded: int

class EvalStep1Response(BaseModel):
    blinded2: int

class EvalStep2Request(BaseModel):
    uid: int
    did: int
    unblinded1: int

class EvalStep2Response(BaseModel):
    query_result: Dict[int, str]

class NewStudentRequest(BaseModel):
    uid: int
    SData: Dict[str, str]  # {proposed_id: data_val}

class NewStudentResponse(BaseModel):
    newDataIDList: List[int]

class ExistingStudentRequest(BaseModel):
    uid: int
    dataIDs: List[int]

class ExistingStudentResponse(BaseModel):
    currentData: Dict[int, str]

class UpdateExistingRequest(BaseModel):
    uid: int
    SData: Dict[str, str]

class UpdateExistingResponse(BaseModel):
    result: str

class EditStep2Request(BaseModel):
    uid: int
    did: int
    blinded: int

class EditStep2Response(BaseModel):
    blinded2: int

class EditStep3Request(BaseModel):
    uid: int
    did: int
    unblinded1: int
    addOrRemove: int
    dataIDs: List[str]

class EditStep3Response(BaseModel):
    result: str

# endpoints

@app.post("/announce")
def announce(req: AnnounceRequest):
    device_locations[(req.uid, req.did)] = (req.ip, req.port)
    return {"result": "ok"}

@app.get("/device_location", response_model=DeviceLocationResponse)
def device_location(uid: int = Query(...), did: int = Query(...)) -> Dict[str, Union[str, int]]:
    key = (uid, did)
    if key not in device_locations:
        raise HTTPException(status_code=404, detail="Device not found")
    if uid != 1 and userDB[uid]["devices"][did]["DSK"] == None:
        raise HTTPException(status_code=403, detail="Device has been revoked")
    ip, port = device_locations[key]
    return {"ip": ip, "port": port}

@app.get("/config")
def get_config():
    return {"p": P}

@app.post("/super_init", response_model=SuperInitResponse)
def super_init(req: SuperInitRequest):
    UID, DID = 1, 1
    userDB[UID] = {
            "cert": None,
            "name": req.name,
            "devices": {},
            "studentData": {},
            "indexData": {},
        }
    return {"UID": UID, "DID": DID}

@app.post("/init")
def init_device(req: InitRequest):
    if req.uid in userDB and req.did in userDB[req.uid]["devices"]:
        raise HTTPException(status_code=400, detail="Device already initialized")
    
    userDB[req.uid] = {
            "cert": None,
            "name": req.name,
            "devices": {},
            "studentData": {},
            "indexData": {},
        }

    # generate device values
    constant = random.randint(1, 100000)
    DSK = req.unused * constant

    # decode school certificate
    try:
        cert_bytes = base64.b64decode(req.schoolCert_str.encode())
        public_key = serialization.load_pem_public_key(cert_bytes)
        schoolCert = cast(dsa.DSAPublicKey, public_key)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid school certificate")

    # store user info
    userDB[req.uid]["cert"] = schoolCert
    userDB[req.uid]["devices"][req.did] = {"DSK": DSK, "constant": constant}
    userDB[req.uid]["name"] = req.name

    return {"result": "initialized"}

@app.post("/register", response_model=RegisterResponse)
def register_device(req: RegisterRequest):
    if req.uid not in userDB or req.did not in userDB[req.uid]["devices"]:
        raise HTTPException(status_code=400, detail="Device not registered")

    devices = userDB[req.uid]["devices"]
    DSK = devices[req.did]["DSK"]
    constant = devices[req.did]["constant"]
    if DSK is None:
        raise HTTPException(status_code=403, detail="Device revoked")

    new_DSK = req.unused * constant
    if any(v["DSK"] == new_DSK for v in devices.values()):
        raise HTTPException(status_code=409, detail="DSK generated is invalid")

    # generate unique DID
    new_did = random.randint(10**9, 10**10 - 1)
    while new_did in devices:
        new_did = random.randint(10**9, 10**10 - 1)

    devices[new_did] = {"DSK": new_DSK, "constant": constant}
    return {"new_did": new_did}

@app.get("/revoke_list", response_model=RevokeListResponse)
def revoke_list(uid: int = Query(...), did: int = Query(...)):
    if uid not in userDB or did not in userDB[uid]["devices"]:
        raise HTTPException(status_code=400, detail="Device not registered")
    if userDB[uid]["devices"][did]["DSK"] is None:
        raise HTTPException(status_code=403, detail="Device revoked")
    dids = [d for d, v in userDB[uid]["devices"].items() if v["DSK"] is not None]
    return {"dids": dids}

@app.post("/revoke", response_model=RevokeResponse)
def revoke(req: RevokeRequest):
    if req.uid not in userDB or req.did not in userDB[req.uid]["devices"]:
        raise HTTPException(status_code=400, detail="Device not registered")
    if userDB[req.uid]["devices"][req.did]["DSK"] is None:
        raise HTTPException(status_code=403, detail="Current device revoked")

    if req.revoke_did not in userDB[req.uid]["devices"]:
        raise HTTPException(status_code=404, detail="Target device not found")
    if userDB[req.uid]["devices"][req.revoke_did]["DSK"] is None:
        raise HTTPException(status_code=409, detail="Target device already revoked")

    schoolCert = userDB[req.uid]["cert"]
    if schoolCert is None:
        raise HTTPException(status_code=400, detail="School certificate not found for this user")

    msg_bytes = req.message_str.encode()
    sig_bytes = base64.b64decode(req.msgSignature_str.encode())

    try:
        schoolCert.verify(sig_bytes, msg_bytes, hashes.SHA256())
    except InvalidSignature:
        raise HTTPException(status_code=403, detail="Invalid signature from school")
    userDB[req.uid]["devices"][req.revoke_did]["DSK"] = None
    return {"result": "Revocation completed"}

@app.post("/super_revoke", response_model=SuperRevokeResponse)
def super_revoke(req: SuperRevokeRequest):
    try:
        userDB[req.uid] = UserDBEntry(
            cert=None,
            name=userDB[req.uid]["name"],
            devices={did: {"DSK": None, "constant": dev["constant"]} 
                     for did, dev in userDB[req.uid]["devices"].items()},
            studentData={},
            indexData={}
        )
    except KeyError:
        raise HTTPException(status_code=400, detail="Target school not found")
    return {"result": "Revocation completed."}

@app.post("/eval/step1", response_model=EvalStep1Response)
def eval_step1(req: EvalStep1Request):
    if req.uid not in userDB or req.did not in userDB[req.uid]["devices"]:
        raise HTTPException(status_code=400, detail="Device not registered")
    DSK = userDB[req.uid]["devices"][req.did]["DSK"]
    if DSK is None:
        raise HTTPException(status_code=403, detail="Device revoked")

    r2 = random_coprime(P - 1)
    r2_store[(req.uid, req.did)] = r2
    blinded2 = pow(req.blinded, DSK * r2, P)
    return {"blinded2": blinded2}

@app.post("/eval/step2", response_model=EvalStep2Response)
def eval_step2(req: EvalStep2Request):
    key = (req.uid, req.did)
    if key not in r2_store:
        raise HTTPException(status_code=400, detail="No pending evaluation")
    r2 = r2_store.pop(key)
    r2_inv = pow(r2, -1, P - 1)
    final_value = pow(req.unblinded1, r2_inv, P)

    user_index = userDB[req.uid]["indexData"]
    user_student = userDB[req.uid]["studentData"]

    if final_value not in user_index:
        raise HTTPException(status_code=400, detail="Encrypted index not found")

    query_result = {data_id: user_student[data_id] for data_id in user_index[final_value]}
    return {"query_result": query_result}

@app.post("/edit/new", response_model=NewStudentResponse)
def add_new_students(req: NewStudentRequest):
    user_student = userDB[req.uid]["studentData"]
    new_ids: List[int] = []

    for data_id_str, data_val in req.SData.items():
        data_id = int(data_id_str)
        data_id = random.randint(10**7, 10**8 - 1)
        while data_id in user_student:
            data_id = random.randint(10**7, 10**8 - 1)
        user_student[data_id] = data_val
        new_ids.append(data_id)

    return {"newDataIDList": new_ids}

@app.post("/edit/existing", response_model=ExistingStudentResponse)
def get_existing_students(req: ExistingStudentRequest):
    user_student = userDB[req.uid]["studentData"]
    current_data: Dict[int, str] = {}

    for data_id in req.dataIDs:
        if data_id not in user_student:
            raise HTTPException(status_code=400, detail=f"DataID {data_id} not found")
        current_data[data_id] = user_student[data_id]

    return {"currentData": current_data}

@app.post("/edit/existing/update", response_model=UpdateExistingResponse)
def update_existing_students(req: UpdateExistingRequest):
    user_student = userDB[req.uid]["studentData"]

    for data_id_str, data_val in req.SData.items():
        data_id = int(data_id_str)  # cast to int
        if data_id not in user_student:
            raise HTTPException(status_code=400, detail=f"DataID {data_id} not found")
        user_student[data_id] = data_val

    return {"result": "success"}

@app.post("/edit/step2", response_model=EditStep2Response)
def edit_step2(req: EditStep2Request):
    if req.uid not in userDB or req.did not in userDB[req.uid]["devices"]:
        raise HTTPException(status_code=400, detail="Device not registered")
    DSK = userDB[req.uid]["devices"][req.did]["DSK"]
    if DSK is None:
        raise HTTPException(status_code=403, detail="Device revoked")

    r2 = random_coprime(P - 1)
    r2_store[(req.uid, req.did)] = r2
    blinded2 = pow(req.blinded, DSK * r2, P)
    return {"blinded2": blinded2}

@app.post("/edit/step3", response_model=EditStep3Response)
def edit_step3(req: EditStep3Request):
    key = (req.uid, req.did)
    if key not in r2_store:
        raise HTTPException(status_code=400, detail="No pending edit")
    r2 = r2_store.pop(key)
    r2_inv = pow(r2, -1, P - 1)
    final_value = pow(req.unblinded1, r2_inv, P)

    user_index = userDB[req.uid]["indexData"]
    int_ids = [int(id_str) for id_str in req.dataIDs]

    if final_value not in user_index:
        if req.addOrRemove == 1:
            user_index[final_value] = int_ids
        else:
            raise HTTPException(status_code=400, detail="Cannot remove from non-existent index")
    else:
        if req.addOrRemove == 1:
            user_index[final_value].extend(id_ for id_ in int_ids if id_ not in user_index[final_value])
        else:
            for id_ in int_ids:
                if id_ not in user_index[final_value]:
                    raise HTTPException(status_code=400, detail="DataID not in index")
                user_index[final_value].remove(id_)

    return {"result": "successful"}



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)