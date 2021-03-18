import hashlib
from binascii import hexlify, unhexlify
from os import urandom


class WinternitzSignature:
    def __init__(self):
        self.generateKeys()
        self.used = False

    def generateKeys(self):
        privKey = []
        pubKey = []

        for i in range(32):
            h = WinternitzSignature.randomKey()
            privKey.append(h)
            for j in range(256):
                h = self.sha256(h)
            pubKey.append(h)

        self.privateKey = privKey
        self.publicKey = pubKey

    def sign(self, msg):
        if(self.used):
            print("Key has already been used")
        else:
            self.used = True
        hashedMsg = WinternitzSignature.sha256Bytes(msg)
        signature = []
        print('Signing message for "'+msg+'"')
        for i in range(len(hashedMsg)):
            key = self.privateKey[i]
            for j in range(256-hashedMsg[i]):
                key = self.sha256(key)
            signature.append(key)
        return signature

    def verify(self, msg, signature):
        hashedMsg = WinternitzSignature.sha256Bytes(msg)
        msgPubKey = []
        for i in range(len(hashedMsg)):
            key = signature[i]
            for j in range(hashedMsg[i]):
                key = self.sha256(key)
            msgPubKey.append(key)
        if msgPubKey == self.publicKey:
            return True
        else:
            return False

    @staticmethod
    def concatenateListToString(valueList):
        if type(valueList) is list:
            result = ''
            for value in valueList:
                result += WinternitzSignature.concatenateListToString(value)
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
