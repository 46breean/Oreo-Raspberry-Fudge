import random
import hashlib
from fastapi import FastAPI
ClientInitialized = []
ClientStartRegistration = []
ServerKeys = {}
Registered = []
RegisteredDevices = {}

app = FastAPI()

def client_initialize(uid,did,rid):
  if (uid,did,rid) in ClientInitialized:
    return("User " + str(uid) + " has been previsouly initialized.")
    flag1 = False
  else:
    ClientInitialized.append((uid,did,rid))

def server_initialize(uid,did,rid):
  if (uid,did,rid) in Registered:
    return("Device " + str(did) + " has been previously registered.")
    flag1 = False
  else:
    RegisteredDevices[(uid,rid)]=(did)
    Registered.append((uid,did,rid))
    return("User " + str(uid) + " has been successfully initialized and device " + str(did) + " has been registered.")

def client_start_registration(uid,did1,did2,rid):
  if (uid,did1,rid) not in ClientInitialized:
    return("User " + str(uid) + " has not been initialized.")
    flag1 = False
  else:
    ClientStartRegistration.append((uid,did1,did2,rid))

def client_finish_registration(uid,did1,did2,rid):
  if (uid,did2,rid) in ClientInitialized:
    return("Device " + str(did2) + " has been previously registered.")
    flag1 = False
  elif (uid,did1,did2,rid) not in ClientStartRegistration:
    return("User " + str(uid) + " has not started registration.")
    flag1 = False
  else:
    ClientInitialized.append((uid,did2,rid))

def server_accept_registration(uid,did1,did2,rid):
  if (uid,did2,rid) in Registered:
    return("Device " + str(did2) + " has been previously registered.")
    flag1 = False
  elif (uid,did1,did2,rid) not in ClientStartRegistration:
    return("User " + str(uid) + " has not started registration.")
    flag1 = False
  elif (uid,did1,rid) not in Registered:
    return("User " + str(uid) + " does not have any previously registered device.")
  else:
    originalDevice = RegisteredDevices[(uid,rid)]
    newDevice=[]
    for i in originalDevice:
      newDevice.append(i)
    newDevice.append(did2)
    RegisteredDevices[(uid,rid)]=newDevice
    Registered.append((uid,did2,rid))
    return("User " + str(uid) + " has successfully registered device " + str(did2) + ".")

def server_revocation(uid,did,rid):
  if (uid,did,rid) not in Registered:
    return("Device " + str(did) + " has not been registered.")
  else:
    originalDevice = RegisteredDevices[(uid,rid)]
    newDevice=[]
    for i in originalDevice:
      newDevice.append(i)
    newDevice.remove(did)
    RegisteredDevices[(uid,rid)]=newDevice
    Registered.remove((uid,did,rid))
    return("Device " + str(did) + " has been successfully revoked.")

@app.get("/")
def fn_selection():
  flag1 = True
  flag2 = True

  while flag2 == True:
    command=input("Enter 1 to initialize a new client, 2 to register a new device, 3 to revoke a current device, and 4 to check all registered clients.")
    if command=="1":
      uid=input("Username:")
      did=input("Device:")
      rid=random.randint(1,10)
      if uid in ServerKeys.keys():
        print("User " + str(uid) + " has already been initialized.")
        flag1 = False
      else:
        ServerKeys[uid] = rid
      if flag1 == True:
        print(client_initialize(uid,did,rid))
      if flag1 == True:
        print(server_initialize(uid,did,rid))
      flag1 = True
    elif command=="2":
      uid=input("Username:")
      did1=input("Original device:")
      did2=input("New device:")
      if uid not in ServerKeys.keys():
        print("User " + str(uid) + " has not been initialized.")
        flag1 = False
      else:
        rid = ServerKeys[uid]
      if flag1 == True:
        print(client_start_registration(uid,did1,did2,rid))
      if flag1 == True:
        print(client_finish_registration(uid,did1,did2,rid))
      if flag1 == True:
        print(server_accept_registration(uid,did1,did2,rid))
      flag1 = True
    elif command=="3":
      uid=input("Username:")
      did=input("Device to revoke:")
      rid = ServerKeys[uid]
      print(server_revocation(uid,did,rid))
    elif command=="4":
      print(RegisteredDevices)
    else:
      print("Invalid command, please try again.")

fn_selection()