import random, math, uvicorn, pickle, os
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Dict, Tuple, Optional
from contextlib import asynccontextmanager

P = 29996224275833 # prime modulus
userDataDB: Dict[Tuple[int, int], Optional[int]] = {}
userConstantDB: Dict[Tuple[int, int], Optional[int]] = {}
nameDB: Dict[Tuple[int, int], str] = {}
indexDataDB: Dict[int, list[int]] = {}
studentDataDB: Dict[int, str] = {}
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

# FastAPI app
app = FastAPI(title="Encrypted Indexing Server", version="1.0.0", lifespan = lifespan)

# models
class AnnounceRequest(BaseModel):
    UID: int
    DID: int
    ip: str
    port: int

class DeviceLocationRequest(BaseModel):
    uid: int
    did: int

class DeviceLocationResponse(BaseModel):
    ip: str
    port: int

class InitRequest(BaseModel):
    unused: int
    name: str = Query(...)

class InitResponse(BaseModel):
    UID: int
    DID: int

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

class SuperRevokeRequest(BaseModel):
    uid: int

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
    device_locations[(req.UID, req.DID)] = (req.ip, req.port)
    return {"status": "ok"}

@app.get("/device_location", response_model = DeviceLocationResponse)
def device_location(req: DeviceLocationRequest) -> dict[str, int|str]:
    if (req.uid, req.did) not in device_locations:
        raise HTTPException(status_code=404, detail="Device not found")
    ip = device_locations[(req.uid, req.did)][0]
    port = device_locations[(req.uid, req.did)][1]
    return {"ip": ip, "port": port}

@app.get("/config")
def get_config():
    return {"p": P}

@app.post("/init", response_model=InitResponse)
def init_device(req: InitRequest):
    constant = random.randint(1, 100000)
    UID = random.randint(10**9, 10**10 - 1)
    DID = random.randint(10**9, 10**10 - 1)
    DSK = req.unused*constant
    userConstantDB[(UID, DID)] = constant
    userDataDB[(UID, DID)] = DSK
    nameDB[(UID, DID)] = req.name
    return {"UID": UID, "DID": DID}

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
def revoke_list(req: RevokeListRequest):
    key = (req.uid, req.did)
    if key not in userDataDB:
        raise HTTPException(status_code=400, detail="Current device not registered")
    if userDataDB[key] is None:
        raise HTTPException(status_code=403, detail="Current device has been revoked")

    dids = [d for (u, d), dsk in userDataDB.items() if u == req.uid and dsk is not None]
    return {"DIDs": dids}

@app.post("/revoke")
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

    userDataDB[target] = None
    return {"Status": "Revocation Completed"}

@app.post("/super_revoke")
def super_revoke(req: SuperRevokeRequest):
    for (k,_) in userDataDB.items():
        if k[0] == req.uid:
            userDataDB[k] = None
    return {"Status": "Revocation Completed"}
    
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
    
    DataID = indexDataDB[final_value]
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

def start_server():
    uvicorn.run(app, host="0.0.0.0", port=8000)