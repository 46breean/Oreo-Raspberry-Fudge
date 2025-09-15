from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
import random, math
from typing import Dict, Tuple, Optional
import random

userDataDB: Dict[Tuple[int, int], Optional[int]] = {}
nameDB, indexDataDB, encDB = {}, {}, {}
r2_store: Dict[Tuple[int, int], int] = {}

# prime modulus
P = 29996224275833

# FastAPI app
app = FastAPI(title="Encrypted Indexing Server", version="1.0.0")

@app.get("/")
def read_root():
    return {"message": "Server is running"}

def random_coprime(p_minus_1: int) -> int:
    while True:
        r = random.randint(2, p_minus_1)
        if math.gcd(r, p_minus_1) == 1:
            return r

# models
class InitResponse(BaseModel):
    UID: int
    DID: int
    name: str

class RegisterRequest(BaseModel):
    uid: int
    did: int
    factor: int

class RegisterResponse(BaseModel):
    uid: int
    new_did: int

class RevokeListResponse(BaseModel):
    dids: list[int]

class RevokeRequest(BaseModel):
    uid: int
    did: int
    revoke_did: int

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
    final: int

# endpoints
device_locations = {}  # (uid, did) -> (ip, port)

@app.post("/announce")
def announce(uid: int, did: int, ip: str, port: int):
    device_locations[(uid, did)] = (ip, port)
    return {"status": "ok"}

@app.get("/device_location")
def device_location(uid: int, did: int):
    if (uid, did) not in device_locations:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"ip": device_locations[(uid, did)][0], "port": device_locations[(uid, did)][1]}

@app.get("/config")
def get_config():
    return {"p": P}

@app.post("/init", response_model=InitResponse)
def init_device(name: str = Query(...)):
    UID = random.randint(10**9, 10**10 - 1)
    DID = random.randint(10**9, 10**10 - 1)
    DSK = random.randint(1, 10**6)
    userDataDB[(UID, DID)] = DSK
    nameDB[(UID, DID)] = name
    return {"UID": UID, "DID": DID, "name": name}


@app.post("/register", response_model=RegisterResponse)
def register_device(req: RegisterRequest):
    key = (req.uid, req.did)
    DSK = userDataDB[key]
    if key not in userDataDB:
        raise HTTPException(status_code=400, detail="Current device not registered")
    if DSK is None:
        raise HTTPException(status_code=403, detail="Current device has been revoked")
    
    existing_dsks = [dsk for (u, d), dsk in userDataDB.items() if u == req.uid] # current code doesn't check if dsk clashes, will fix in
    new_dsk = DSK * req.factor
    if new_dsk in existing_dsks:
        raise HTTPException(status_code=409, detail="Factor generated is invalid")


    existing_dids = [d for (u, d), _ in userDataDB.items() if u == req.uid]
    while True:
        new_did = random.randint(10**9, 10**10 - 1)
        if new_did not in existing_dids:
            break

    userDataDB[(req.uid, new_did)] = new_dsk
    return {"uid": req.uid, "new_did": new_did}

@app.get("/revoke_list", response_model=RevokeListResponse)
def revoke_list(uid: int = Query(...), did: int = Query(...)):
    key = (uid, did)
    if key not in userDataDB:
        raise HTTPException(status_code=400, detail="Current device not registered")
    if userDataDB[key] is None:
        raise HTTPException(status_code=403, detail="Current device has been revoked")

    dids = [d for (u, d), dsk in userDataDB.items() if u == uid and dsk is not None]
    return {"dids": dids}

@app.post("/revoke")

def revoke(req: RevokeRequest):

    current = (req.uid, req.did)
    target = (req.uid, req.revoke_did)
    if current not in userDataDB:
        raise HTTPException(status_code=400, detail="Current device not registered")
    elif userDataDB[current] is None:
        raise HTTPException(status_code=403, detail="Current device has been revoked")
    if target not in userDataDB:
        raise HTTPException(status_code=404, detail="Target device not found")
    elif userDataDB[target] is None:
        raise HTTPException(status_code=409, detail="Target device already revoked")

    userDataDB[target] = None
    return {"Status": "Revocation Completed"}

@app.post("/eval/step1", response_model=EvalStep1Response)
def eval_step1(req: EvalStep1Request):
    key = (req.uid, req.did)
    DSK = userDataDB[key]    
    if key not in userDataDB:
        raise HTTPException(status_code=400, detail="Current device not registered")
    elif userDataDB[key] is None:
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
    final_value = pow(req.unblinded1, r2_inv, P)
    return {"final": final_value}
