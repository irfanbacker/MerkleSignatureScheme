import hashlib
from binascii import hexlify, unhexlify
from os import urandom


class LamportOTS:
    def __init__(self):
        self.generateKeys()
        self.used = False

    def generateKeys(self):
        self.zeroPrivateKey = [LamportOTS.randomKey() for i in range(256)]
        self.onePrivateKey = [LamportOTS.randomKey() for i in range(256)]
        self.zeroPublicKey = [LamportOTS.sha256(
            b) for b in self.zeroPrivateKey]
        self.onePublicKey = [LamportOTS.sha256(b) for b in self.onePrivateKey]

    def sign(self, msg):
        if(self.used):
            print("Key has already been used")
        else:
            self.used = True
        binaryHashedMsg = LamportOTS.hashMessageToBinary(msg)
        signature = []
        print('Signing message for "'+msg+'"')
        for i in range(len(binaryHashedMsg)):
            bit = binaryHashedMsg[i]
            signature.append(self.privateKey[bit][i])
        return signature

    def verify(self, msg, signature):
        binaryHashedMsg = LamportOTS.hashMessageToBinary(msg)
        for i in range(len(binaryHashedMsg)):
            bit = binaryHashedMsg[i]
            if(LamportOTS.sha256(signature[i]) != self.publicKey[bit][i]):
                return False
        return True

    @property
    def privateKey(self):
        return [self.zeroPrivateKey, self.onePrivateKey]

    @property
    def publicKey(self):
        return [self.zeroPublicKey, self.onePublicKey]

    @staticmethod
    def concatenateListToString(valueList):
        if type(valueList) is list:
            result = ''
            for value in valueList:
                result += LamportOTS.concatenateListToString(value)
                return result
        else:
            return valueList

    @staticmethod
    def randomKey(n=32):
        return hexlify(urandom(n)).decode('utf-8')

    @staticmethod
    def sha256(textValue):
        return hashlib.sha256(textValue.encode('utf-8')).hexdigest()

    @staticmethod
    def sha256Bytes(textValue):
        return hashlib.sha256(textValue.encode('utf-8')).digest()

    @staticmethod
    def hexToBinary(hashedBytes):
        binaryMsg = []
        for byte in hashedBytes:
            i = 128
            while(i > 0):
                if byte & i != 0:
                    binaryMsg.append(1)
                else:
                    binaryMsg.append(0)
                i = int(i/2)
        return binaryMsg

    @staticmethod
    def hashMessageToBinary(msg):
        hashedBytesMsg = LamportOTS.sha256Bytes(msg)
        return LamportOTS.hexToBinary(hashedBytesMsg)
