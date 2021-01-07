#! /usr/bin/env python

from cryptography.hazmat.primitives.asymmetric import x25519
import base64
import binascii
import pyglome
import sys

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'usage: {sys.argv[0]} PRIV-KEY-HEX URL-PATH')
        sys.exit(1)

    priv_key = x25519.X25519PrivateKey.from_private_bytes(binascii.a2b_hex(sys.argv[1]))
    url_path = sys.argv[2]

    if not url_path.startswith('/v1/') or len(url_path.split('/')) < 4:
        print('error: invalid URL path (or unsupported version)')
        sys.exit(1)

    msg = url_path.split('/', 3)[3].rstrip('/').encode('utf-8')
    handshake = base64.urlsafe_b64decode(url_path.split('/')[2])
    if len(handshake) != 33:
        print('error: invalid handshake token (wrong length)')
        sys.exit(1)

    pub_key = x25519.X25519PublicKey.from_public_bytes(handshake[1:])

    glome = pyglome.Glome(pub_key, priv_key)
    tag = glome.tag(msg, counter=0)
    print(base64.urlsafe_b64encode(tag).decode('utf-8'))
