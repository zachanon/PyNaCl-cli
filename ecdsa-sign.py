from nacl import signing, encoding

def sign(keyfile, messagefile):

  with open(keyfile) as file:
    pk = file.readline().strip().encode('utf-8')
  with open(messagefile) as file:
    msg = file.readline().encode('utf-8')

  encoder = encoding.HexEncoder
  signer = signing.SigningKey(pk, encoder=encoder)
  
  signed = signer.sign(msg, encoder=encoder)
  verify_key = signer.verify_key.encode(encoder=encoder)

  with open('vkey.pem', 'w') as file:
    file.write(verify_key.decode())
  with open('smsg.pem', 'w') as file:
    file.write(signed.decode())

def verify(verify_key, signed_message):

  with open(verify_key) as file:
    vkey = file.readline().strip().encode('utf-8')
  with open(signed_message) as file:
    smsg = file.readline().strip().encode('utf-8')
  
  encoder = encoding.HexEncoder

  verifier = signing.VerifyKey(vkey, encoder=encoder)
  return verifier.verify(smsg, encoder=encoder)

sign('key.pem', 'msg.pem')
verify('vkey.pem', 'smsg.pem')