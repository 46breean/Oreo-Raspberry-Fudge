import hashlib
import random

rainbowTable = {}

k = 100
chainCount = 0

def H(message):
  m = hashlib.md5()
  m.update(message.encode("utf-8"))
  return(m.hexdigest())

def R(message):
  return(message[0:6])

def gen():
  genCount = 1
  m = ""
  while genCount < 440:
    m = str(m + str(random.randint(0,1)))
    genCount += 1
  return str(m)

while chainCount < 100:
  hashCount = 0
  value = gen()
  message = value
  while hashCount < k:
    message = H(message)
    message = R(message)
    hashCount += 1
  rainbowTable[value] = message
  chainCount += 1

print(rainbowTable)

print("Start Testing")

hashCount = 1

while hashCount < 2**17:
  message = gen()
  hashValue = H(message)
  for i in rainbowTable.keys():
    if rainbowTable[i] == hashValue:
      message1 = i
      flag = True
      while flag == True:
        message2 = H(message1)
        message1 = R(message2)
        if message1 == hashValue:
          flag == False
          collision = message2
        if message2 == hashValue:
          flag == False
          collision = message1
      print("Value 1: " + str(message))
      print("Value 2: " + str(collision))
      print("Common Hash: " + str(hashValue))
      break
  hashCount += 1

print("End Testing")
