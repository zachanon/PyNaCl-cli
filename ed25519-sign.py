import argparse
from sys import stdin
from nacl import signing, encoding

def sign(keyfile, message):

  with open(keyfile) as file:
    pk = file.readline().strip().encode('utf-8')
  
  encoder = encoding.HexEncoder
  signer = signing.SigningKey(pk, encoder=encoder)
  
  if message:
    msg = message.encode('utf-8')
  else:
    msg = stdin.read().encode('utf-8')

  signed = signer.sign(msg, encoder=encoder)
  print(signed.decode())

def verify(verify_key, signed_message):

  with open(verify_key) as file:
    vkey = file.readline().strip().encode('utf-8')
  with open(signed_message) as file:
    smsg = file.readline().strip().encode('utf-8')
  
  encoder = encoding.HexEncoder

  verifier = signing.VerifyKey(vkey, encoder=encoder)
  return verifier.verify(smsg, encoder=encoder)

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument("keyfile")
  parser.add_argument("--message")

  args = parser.parse_args()
  sign(args.keyfile, args.message)
