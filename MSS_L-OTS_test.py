import lamport
import merkle

totalCountofOTSkeys = 4
keyPairs = [lamport.LamportOTS() for i in range(totalCountofOTSkeys)]

senderMerkleTree = merkle.MSS(leavesCount=totalCountofOTSkeys)
for i in range(totalCountofOTSkeys):
    senderMerkleTree.addNode((0, i), keyPairs[i].publicKey, isHashed=False)
senderMerkleTree.buildTree()
treeRootPublicKey = senderMerkleTree.RootPublicKey()

currentOTSkeyIndex = 3
merkleSignature = []
senderMessage = "testing123"
messageSignature = keyPairs[currentOTSkeyIndex].sign(senderMessage)
merkleSignature.append(messageSignature)
merkleSignature.append(keyPairs[currentOTSkeyIndex].publicKey)
merkleSignature.append(senderMerkleTree.getAuthNodesValue(currentOTSkeyIndex))

########################################################################################################################################
print('-------------------------------------------------------------------------')
recievedRootPublicKey = treeRootPublicKey
recievedMessage = senderMessage
recievedMerkleSignature = merkleSignature

# Example 1 - wrong message
print('Verifying message "testing" with message signature')
result = keyPairs[currentOTSkeyIndex].verify('testing', messageSignature)
print("Message verification result: " + str(result))

# Example 2 - wrong publickey
print('\nVerifying message "' + recievedMessage + '" with message signature')
result = keyPairs[currentOTSkeyIndex].verify(
    recievedMessage, recievedMerkleSignature[0])
print("Message verification result: " + str(result))
if result:
    recieverMerkleTree = merkle.MSS(leavesCount=totalCountofOTSkeys)
    recieverMerkleTree.addNode(
        (0, currentOTSkeyIndex), recievedMerkleSignature[0], isHashed=False)
    recieverMerkleTree.buildTree()

    for i, (level, index) in enumerate(recieverMerkleTree.getAuthNodesPosition(currentOTSkeyIndex)):
        recieverMerkleTree.addNode(
            (level, index), recievedMerkleSignature[2][i])
    recieverMerkleTree.buildTree()

    result = recieverMerkleTree.RootPublicKey() == recievedRootPublicKey
    print("Merkle signature verification: " + str(result))
    print('Invalid public key used!')

# Example 3 - Correct signatures
print('\nVerifying message "' + recievedMessage + '" with message signature')
result = keyPairs[currentOTSkeyIndex].verify(
    recievedMessage, recievedMerkleSignature[0])
print("Message verification result: " + str(result))
if result:
    recieverMerkleTree = merkle.MSS(leavesCount=totalCountofOTSkeys)
    result = recieverMerkleTree.verify(currentOTSkeyIndex=currentOTSkeyIndex,
                                       recievedMerkleSignature=recievedMerkleSignature, recievedRootPublicKey=recievedRootPublicKey)
    print("Merkle signature verification: " + str(result))
