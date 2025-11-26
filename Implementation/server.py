import random, math, uvicorn, pickle, os, base64
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Dict, Tuple, Optional, cast
from contextlib import asynccontextmanager
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization

P = 29996224275833 # prime modulus
userDataDB: Dict[Tuple[int, int], Optional[int]] = {}
userConstantDB: Dict[Tuple[int, int], Optional[int]] = {}
userCertDB: Dict[int, dsa.DSAPublicKey] = {}
nameDB: Dict[Tuple[int, int], str] = {}
indexDataDB: Dict[int, list[int]] = {} # index:list of dataID
studentDataDB: Dict[int, str] = {} # dataID:student info
r2_store: Dict[Tuple[int, int], int] = {}
device_locations: Dict[Tuple[int, int], Tuple[str, int]] = {}
state: Dict[str, object] = {
    "userDataDB": userDataDB,
    "userConstantDB": userConstantDB,
    "nameDB": nameDB,
    "indexDataDB": indexDataDB,
    "studentDataDB": studentDataDB,
    "r2_store": r2_store,
    "device_locations": device_locations,
}

def random_coprime(p_minus_1: int) -> int:
    while True:
        r = random.randint(2, p_minus_1)
        if math.gcd(r, p_minus_1) == 1:
            return r

def save_state(state: dict[str, object], filename:str ='server_state.pk1'):
    with open(filename, "wb") as f:
        pickle.dump(state, f)

def load_state(filename:str = 'server_state.pk1'):
    if not os.path.exists(filename):
        return None
    with open(filename, "rb") as f:
        return pickle.load(f)

@asynccontextmanager
async def lifespan(app:FastAPI):
    start_state = load_state()
    if start_state:
        print("Saved state loaded.")
    else:
        print("Fresh state loaded.")
    yield
    save_state(state)

app = FastAPI(title="Encrypted Indexing Server", version="1.0.0") #, lifespan = lifespan

# models
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

class RevokeListRequest(BaseModel):
    uid: int = Query(...)
    did: int = Query(...)
    
class RevokeListResponse(BaseModel):
    dids: list[int]

class RevokeRequest(BaseModel):
    uid: int
    did: int
    revoke_did: int
    message_str: str
    msgSignature_str: str
    deviceCert_str: str
    deviceSignature_str: str

class RevokeResponse(BaseModel):
    result: str

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
    query_result: dict[int, str]

class EditStep1Request(BaseModel):
    dataEntryType: int
    SData: dict[str, str]

class EditStep1Response(BaseModel):
    newDataIDList: list[int]

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
    dataIDs: list[str]

class EditStep3Response(BaseModel):
    result: str

# endpoints
@app.post("/announce")
def announce(req: AnnounceRequest):
    device_locations[(req.uid, req.did)] = (req.ip, req.port)
    return

@app.get("/device_location", response_model = DeviceLocationResponse)
def device_location(uid: int = Query(...), did: int = Query(...)) -> dict[str, int|str]:
    if (uid, did) not in device_locations:
        raise HTTPException(status_code=404, detail="Device not found")
    
    ip = device_locations[(uid, did)][0]
    port = device_locations[(uid, did)][1]
    return {"ip": ip, "port": port}

@app.get("/config")
def get_config():
    return {"p": P}

@app.post("/init")
def init_device(req: InitRequest):
    constant = random.randint(1, 100000)
    UID = req.uid
    DID = req.did
    DSK = req.unused*constant
    schoolCert_bytes = base64.b64decode(req.schoolCert_str.encode())
    schoolCert_publicKeyTypes = serialization.load_pem_public_key(schoolCert_bytes)
    schoolCert = cast(dsa.DSAPublicKey, schoolCert_publicKeyTypes)
    userConstantDB[(UID, DID)] = constant
    userDataDB[(UID, DID)] = DSK
    nameDB[(UID, DID)] = req.name
    userCertDB[UID] = schoolCert
    return

@app.post("/super_init", response_model=SuperInitResponse)
def super_init(req: SuperInitRequest):
    UID = 1
    DID = 1
    nameDB[(UID, DID)] = req.name
    return {"UID": UID, "DID": DID}

@app.post("/register", response_model=RegisterResponse)
def register_device(req: RegisterRequest):
    key = (req.uid, req.did)

    if key not in userDataDB:
        raise HTTPException(status_code=400, detail="Current device not registered")

    referral_DSK = userDataDB[key]
    if referral_DSK is None:
        raise HTTPException(status_code=403, detail="Current device has been revoked")
    
    DSK_constant = userConstantDB[key]
    if DSK_constant is None:
        raise HTTPException(status_code=400, detail="Current device not registered.")
    
    existing_dsks = [dsk for (u, _), dsk in userDataDB.items() if u == req.uid]
    new_dsk = DSK_constant * req.unused
    if new_dsk in existing_dsks:
        raise HTTPException(status_code=409, detail="DK generated is invalid")

    existing_dids = [d for (u, d), _ in userDataDB.items() if u == req.uid]
    while True:
        new_did = random.randint(10**9, 10**10 - 1)
        if new_did not in existing_dids:
            break

    userDataDB[(req.uid, new_did)] = new_dsk
    userConstantDB[req.uid, new_did] = DSK_constant
    return {"new_did": new_did}

@app.get("/revoke_list", response_model=RevokeListResponse)
def revoke_list(uid: int = Query(...), did: int = Query(...)):
    key = (uid, did)
    if key not in userDataDB:
        raise HTTPException(status_code=400, detail="Current device not registered")
    if userDataDB[key] is None:
        raise HTTPException(status_code=403, detail="Current device has been revoked")

    dids = [d for (u, d), dsk in userDataDB.items() if u == uid and dsk is not None]
    return {"dids": dids}

@app.post("/revoke", response_model=RevokeResponse)
def revoke(req: RevokeRequest):
    current = (req.uid, req.did)
    if current not in userDataDB:
        raise HTTPException(status_code=400, detail="Current device not registered")
    elif userDataDB[current] is None:
        raise HTTPException(status_code=403, detail="Current device has been revoked")

    target = (req.uid, req.revoke_did)
    if target not in userDataDB:
        raise HTTPException(status_code=404, detail="Target device not found")
    elif userDataDB[target] is None:
        raise HTTPException(status_code=409, detail="Target device already revoked")
    
    print(userCertDB)
    schoolCert = userCertDB[req.uid]
    deviceCert_bytes = base64.b64decode(req.deviceCert_str.encode())
    deviceCert_publicKeyTypes = serialization.load_pem_public_key(deviceCert_bytes)
    deviceCert_DSAPublicKey = cast(dsa.DSAPublicKey, deviceCert_publicKeyTypes)
    deviceSignature_bytes = base64.b64decode(req.deviceSignature_str.encode())
    try:
        schoolCert.verify(deviceSignature_bytes, deviceCert_bytes, hashes.SHA256())
    except InvalidSignature:
        print("Device certificate is invalid. Revocation unauthorised.")
        return
    
    message_bytes = req.message_str.encode()
    signature_bytes = base64.b64decode(req.msgSignature_str.encode())

    try:
        deviceCert_DSAPublicKey.verify(signature_bytes, message_bytes, hashes.SHA256())
    except InvalidSignature:
        print("Signature is invalid. Revocation unauthorised.")
        return
    userDataDB[target] = None
    return {"result": "Revocation completed."}

@app.post("/super_revoke", response_model=SuperRevokeResponse)
def super_revoke(req: SuperRevokeRequest):
    for (k,_) in userDataDB.items():
        if k[0] == req.uid:
            userDataDB[k] = None
    return {"result": "Revocation completed."}
    
@app.post("/eval/step1", response_model=EvalStep1Response)
def eval_step1(req: EvalStep1Request):
    key = (req.uid, req.did)
    if key not in userDataDB:
        raise HTTPException(status_code=400, detail="Current device not registered")
    
    DSK = userDataDB[key]
    if DSK is None:
        raise HTTPException(status_code=403, detail="Current device has been revoked")

    r2 = random_coprime(P - 1)
    r2_store[key] = r2
    blinded2 = pow(req.blinded, DSK * r2, P)
    return {"blinded2": blinded2}

@app.post("/eval/step2", response_model=EvalStep2Response)
def eval_step2(req: EvalStep2Request):
    key = (req.uid, req.did)
    if key not in r2_store:
        raise HTTPException(status_code=400, detail="No pending evaluation for this device")
    
    r2 = r2_store.pop(key)
    r2_inv = pow(r2, -1, P - 1)
    final_value:int = pow(req.unblinded1, r2_inv, P)
    
    if final_value not in indexDataDB:
        raise HTTPException(status_code=400, detail="Encrypted Index not found in this server.")
    
    DataID = indexDataDB[final_value] # returns list of DataIDs
    query_result:dict[int, str] = {}
    
    for ID in DataID:
        intID = int(ID)
        if intID not in studentDataDB:
            raise HTTPException(status_code=400,detail="No student found.")
        SData = studentDataDB[intID]
        query_result[intID] = SData
    return {"query_result": query_result}
    
@app.post("/edit/step1", response_model=EditStep1Response)
def edit_step1(req: EditStep1Request):
    newDataIDList:list[int] = []
    for DataID,Data in req.SData.items():
        DataID = int(DataID)
        if req.dataEntryType == 1:
            DataID = random.randint(10**7, 10**8 - 1)
            while DataID in studentDataDB:
                DataID = random.randint(10*7, 10*8 - 1)
            newDataIDList.append(DataID)
        elif req.dataEntryType == 2:
            if DataID not in studentDataDB:
                raise HTTPException(status_code=400,detail="One or more DataID is not found in the student database. Upload new data and edit existing data separately.")
        studentDataDB[DataID] = Data
    return {"newDataIDList": newDataIDList}

@app.post("/edit/step2", response_model=EditStep2Response)
def edit_step2(req: EditStep2Request):
    key = (req.uid, req.did)
    if key not in userDataDB:
        raise HTTPException(status_code=400, detail="Current device not registered")
    
    DSK = userDataDB[key]
    if DSK is None:
        raise HTTPException(status_code=403, detail="Current device has been revoked")

    r2 = random_coprime(P - 1)
    r2_store[key] = r2
    blinded2 = pow(req.blinded, DSK * r2, P)
    return {"blinded2": blinded2}

@app.post("/edit/step3", response_model=EditStep3Response)
def edit_step3(req: EditStep3Request):
    key = (req.uid, req.did)
    if key not in r2_store:
        raise HTTPException(status_code=400, detail="No pending evaluation for this device")
    
    r2 = r2_store.pop(key)
    r2_inv = pow(r2, -1, P - 1)
    final_value = pow(req.unblinded1, r2_inv, P)
    intDataID = [int(id) for id in req.dataIDs]

    for id in intDataID:
        if final_value in indexDataDB:
            if req.addOrRemove == 1:
                indexDataDB[final_value].append(id)
            else:
                if id not in indexDataDB:
                    raise HTTPException(status_code=400, detail="DataID not found in index database.")
                indexDataDB[final_value].remove(id)
        else:
            if req.addOrRemove == 1:
                indexDataDB[final_value] = intDataID
            else:
                raise HTTPException(status_code=400, detail="You cannot remove data IDs from a non-existent index.")
    return{"result": "successful"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)