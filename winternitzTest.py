import winternitz

senderMessage = 'testing123'
winternitzKeys = winternitz.WinternitzOTS()
messageSignature = winternitzKeys.sign(senderMessage)

###########################################################################################################
print('-------------------------------------------------------------------------')
recievedSignature = messageSignature
recievedMessage = senderMessage

print('Signature verification for "testin1": ',
      winternitzKeys.verify('testin1', recievedSignature))
print('Signature verification for "testIng": ',
      winternitzKeys.verify('testIng', recievedSignature))
print('Signature verification for "testing": ',
      winternitzKeys.verify('testing', recievedSignature))
print('Signature verification for "testing123": ',
      winternitzKeys.verify(recievedMessage, recievedSignature))
