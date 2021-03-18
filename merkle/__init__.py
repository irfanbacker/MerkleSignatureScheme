import hashlib
from binascii import hexlify
from os import urandom
from math import floor, log2


class MerkleTree:
    def __init__(self, leavesCount=4):
        self.leavesCount = leavesCount
        self.levelsCount = None
        self.tree = {}

    def buildTree(self):
        self.levelsCount = int(log2(self.leavesCount)) + 1
        for level in range(self.levelsCount):
            for position in range(int(self.leavesCount/2**level)):
                if level > 0:
                    leftChild = self.tree[(level-1, 2*position)]
                    rightChild = self.tree[(level-1, 2*position+1)]
                    if leftChild != None and rightChild != None:
                        self.tree[(level, position)] = MerkleTree.sha256(
                            leftChild+rightChild)
                    elif (level, position) not in self.tree:
                        self.tree[(level, position)] = None
                elif (level, position) not in self.tree:
                    self.tree[(level, position)] = None

    def RootPublicKey(self):
        return self.tree[(self.levelsCount-1, 0)]

    def addNode(self, position, nodeValue, isHashed=True):
        if type(nodeValue) is list:
            nodeValue = MerkleTree.concatenateListToString(nodeValue)
        if not isHashed:
            nodeValue = MerkleTree.sha256(nodeValue)
        self.tree[position] = nodeValue

    def getAuthNodesPosition(self, keyIndex):
        authPos = []
        for level in range(self.levelsCount-1):
            if keyIndex % 2 == 0:
                authPos.append((level, keyIndex+1))
            else:
                authPos.append((level, keyIndex-1))
            keyIndex = floor(keyIndex/2)
        return authPos

    def getAuthNodesValue(self, keyIndex):
        authPos = self.getAuthNodesPosition(keyIndex)
        authValues = [self.tree[pos] for pos in authPos]
        return authValues

    def verify(self, currentOTSkeyIndex, recievedMerkleSignature, recievedRootPublicKey):
        self.addNode(
            (0, currentOTSkeyIndex), recievedMerkleSignature[1], isHashed=False)
        self.buildTree()

        for i, (level, index) in enumerate(self.getAuthNodesPosition(currentOTSkeyIndex)):
            self.addNode(
                (level, index), recievedMerkleSignature[2][i])
        self.buildTree()

        return self.RootPublicKey() == recievedRootPublicKey

    @staticmethod
    def concatenateListToString(valueList):
        if type(valueList) is list:
            result = ''
            for value in valueList:
                result += MerkleTree.concatenateListToString(value)
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
        hashedBytesMsg = MerkleTree.sha256Bytes(msg)
        return MerkleTree.hexToBinary(hashedBytesMsg)
