from lamport import lamport

keys = lamport.generateKeys()
sig = lamport.signMessage('testing', keys.private)
print('Signature verification for "testin1": ', lamport.verifyMessage('testin1', keys.public, sig))
print('Signature verification for "testin1": ', lamport.verifyMessage('testIng', keys.public, sig))
print('Signature verification for "testing": ', lamport.verifyMessage('testing', keys.public, sig))