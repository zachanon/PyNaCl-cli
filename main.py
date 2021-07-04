from nacl import hash, encoding
import argparse


def main(args):

    hasher = hash.sha256
    msg = args.message.encode('utf-8')

    digest = hasher(msg, encoder=encoding.HexEncoder)
    print(digest.decode())

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash", help='the hash function to use (default sha2 256)')
    parser.add_argument("message", help="message to hash (interpreted as a utf-8 string)", type=str)
    args = parser.parse_args()
    main(args)