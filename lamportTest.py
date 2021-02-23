import lamport

senderMessage = 'testing123'
lamportKeys = lamport.LamportSignature()
messageSignature = lamportKeys.sign(senderMessage)

###########################################################################################################

recievedSignature = messageSignature
recievedMessage = senderMessage

print('Signature verification for "testin1": ', lamportKeys.verify('testin1', recievedSignature))
print('Signature verification for "testIng": ', lamportKeys.verify('testIng', recievedSignature))
print('Signature verification for "testing": ', lamportKeys.verify('testing', recievedSignature))
print('Signature verification for "testing123": ', lamportKeys.verify(recievedMessage, recievedSignature))