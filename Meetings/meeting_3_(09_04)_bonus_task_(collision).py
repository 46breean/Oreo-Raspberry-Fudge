import hashlib
import random

print("Start of code")

def gen():
  genCount = 1
  m = ""
  while genCount < 440:
    m = str(m + str(random.randint(0,1)))
    genCount += 1
  return str(m)

def hash(message):
  m = hashlib.md5()
  m.update(message.encode("utf-8"))
  return(m.hexdigest())

hashCount = 1
hashTable = {}

while hashCount < 2**17:
  message = gen()
  hashValue = hash(message)
  for i in hashTable.keys():
    if hashTable[i] == hashValue:
      value1 = i
      value2 = message
      print("Value 1: " + str(value1))
      print("Value 2: " + str(value2))
      print("Common Hash: " + str(hashValue))
      break
  hashTable[message] = hashValue
  hashCount += 1

print("End of code")
