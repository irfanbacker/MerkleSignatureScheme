import hashlib
import bitstring
from binascii import hexlify, unhexlify
from os import urandom
from math import log, ceil, floor


class WinternitzOTS:
    def __init__(self, w=8):
        if w > 8:
            w = 8
        self.w = w
        self.n = 256//self.w
        self.readUnit = 'uint:{}'.format(self.w)
        self.generateKeys()
        self.used = False

    def generateKeys(self):
        privKey = []
        pubKey = []

        for i in range(self.n):
            h = WinternitzOTS.randomKey()
            privKey.append(h)
            for j in range(2**self.w-1):
                h = self.sha256(h)
            pubKey.append(h)

        self.privateKey = privKey
        self.publicKey = pubKey

    def sign(self, msg):
        if(self.used):
            print("Key has already been used")
        else:
            self.used = True
        hashedMsg = WinternitzOTS.sha256Bytes(msg)
        hashedBitString = bitstring.ConstBitStream(hashedMsg)
        signature = []

        print('Signing message for "'+msg+'"')
        for i in range(self.n):
            key = self.privateKey[i]
            intVal = hashedBitString.read(self.readUnit)
            for j in range(2**self.w-intVal):
                key = self.sha256(key)
            signature.append(key)
        return signature

    def verify(self, msg, signature):
        hashedMsg = WinternitzOTS.sha256Bytes(msg)
        hashedBitString = bitstring.ConstBitStream(hashedMsg)
        msgPubKey = []
        for i in range(self.n):
            key = signature[i]
            intVal = hashedBitString.read(self.readUnit)
            for j in range(intVal-1):
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
                result += WinternitzOTS.concatenateListToString(value)
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


class WinternitzPlusOTS:
    def __init__(self, w=16):
        self.w = w
        self.m = 256
        self.l1 = ceil(self.m/log(w, 2))
        self.l2 = floor(log((self.l1*(w-1)), 2)/log(w, 2)) + 1
        self.l = int(self.l1+self.l2)
        self.generateKeys()
        self.used = False

    def generateKeys(self):
        privKey = []
        pubKey = []

        # Generate keys here

        self.privateKey = privKey
        self.publicKey = pubKey

    def sign(self, msg):
        if(self.used):
            print("Key has already been used")
        else:
            self.used = True
        hashedMsg = WinternitzPlusOTS.sha256Bytes(msg)
        hashedBitString = bitstring.ConstBitStream(hashedMsg)
        signature = []

        print('Signing message for "'+msg+'"')
        # Sign message here
        return signature

    def verify(self, msg, signature):
        hashedMsg = WinternitzPlusOTS.sha256Bytes(msg)
        hashedBitString = bitstring.ConstBitStream(hashedMsg)
        msgPubKey = []
        # Apply logic here

        if msgPubKey == self.publicKey:
            return True
        else:
            return False

    @staticmethod
    def concatenateListToString(valueList):
        if type(valueList) is list:
            result = ''
            for value in valueList:
                result += WinternitzPlusOTS.concatenateListToString(value)
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
