import lamport

senderMessage = 'testing123'
lamportKeys = lamport.LamportOTS()
messageSignature = lamportKeys.sign(senderMessage)

###########################################################################################################
print('-------------------------------------------------------------------------')
recievedSignature = messageSignature
recievedMessage = senderMessage

print('Signature verification for "testin1": ',
      lamportKeys.verify('testin1', recievedSignature))
print('Signature verification for "testIng": ',
      lamportKeys.verify('testIng', recievedSignature))
print('Signature verification for "testing": ',
      lamportKeys.verify('testing', recievedSignature))
print('Signature verification for "testing123": ',
      lamportKeys.verify(recievedMessage, recievedSignature))
