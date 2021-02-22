import hashlib
from binascii import hexlify, unhexlify
from os import urandom

class KeyPair:
    def __init__(self, zeroPrivateKey, onePrivateKey, zeroPublicKey, onePublicKey):
        self.zeroPrivateKey = zeroPrivateKey
        self.onePrivateKey  = onePrivateKey 
        self.zeroPublicKey  = zeroPublicKey 
        self.onePublicKey   = onePublicKey  

    @property
    def private(self):
        return [self.zeroPrivateKey, self.onePrivateKey]

    @property
    def public(self):
        return [self.zeroPublicKey, self.onePublicKey]

def randomKey(n=32):
    return hexlify(urandom(n)).decode('utf-8')

def sha256(textValue):
    return hashlib.sha256(textValue.encode('utf-8')).hexdigest()

def sha256Bytes(textValue):
    return hashlib.sha256(textValue.encode('utf-8')).digest()

def hexToBinary(hashedBytes):
    binaryMsg= []
    for byte in hashedBytes:
            i = 128
            while(i > 0):
                if byte & i != 0:
                    binaryMsg.append(1)
                else:
                    binaryMsg.append(0)
                i = int(i/2)
    return binaryMsg

def hashMessageToBinary(msg):
    hashedBytesMsg = sha256Bytes(msg)
    return hexToBinary(hashedBytesMsg)

def generateKeys():
    zeroPrivateKey = [randomKey() for i in range(256)]
    onePrivateKey = [randomKey() for i in range(256)]
    zeroPublicKey = [sha256(b) for b in zeroPrivateKey]
    onePublicKey = [sha256(b) for b in onePrivateKey]
    return KeyPair(zeroPrivateKey, onePrivateKey, zeroPublicKey, onePublicKey)

def signMessage(msg, privateKey):
    binaryHashedMsg = hashMessageToBinary(msg)
    signature = []
    print('Signing message for "'+msg+'"')
    for i in range(len(binaryHashedMsg)):
        bit = binaryHashedMsg[i]
        signature.append(privateKey[bit][i])
    return signature

def verifyMessage(msg, publicKey, signature):
    binaryHashedMsg = hashMessageToBinary(msg)
    for i in range(len(binaryHashedMsg)):
        bit = binaryHashedMsg[i]
        if(sha256(signature[i]) != publicKey[bit][i]): return False
    return True