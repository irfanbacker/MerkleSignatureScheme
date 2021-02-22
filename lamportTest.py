import lamport

lamportKeys = lamport.LamportSignature()
sig = lamportKeys.sign('testing123')
print('Signature verification for "testin1": ', lamportKeys.verify('testin1', sig))
print('Signature verification for "testIng": ', lamportKeys.verify('testIng', sig))
print('Signature verification for "testing": ', lamportKeys.verify('testing', sig))
print('Signature verification for "testing123": ', lamportKeys.verify('testing123', sig))