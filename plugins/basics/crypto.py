#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
 #the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" This is the library for basic cryptographic features in
    Apache Warble (incubating) nodes. It includes wrappers for
    encrypting, decrypting, signing and verifying using RSA async key
    pairs.
    
    NB: Ideally we'd use SHA256 for hashing, but as that still isn't
    widely supported, we're resorting to SHA1 for now.
"""

import cryptography.hazmat.backends
import cryptography.hazmat.primitives
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.utils
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.hashes
import hashlib

def keypair(bits = 4096):
    """ Generate a private+public key pair for encryption/signing """
    private_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits, # Minimum hould be 4096, puhlease.
        backend=cryptography.hazmat.backends.default_backend()
    )
    return private_key

def loadprivate(filepath):
    """ Loads a private key from a file path """
    with open(filepath, "rb") as key_file:
        private_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=cryptography.hazmat.backends.default_backend()
        )
        return private_key

def loadpublic(filepath):
    """ Loads a public key from a file path """
    with open(filepath, "rb") as key_file:
        public_key = cryptography.hazmat.primitives.serialization.load_pem_public_key(
            key_file.read(),
            backend=cryptography.hazmat.backends.default_backend()
        )
        return public_key

def loads(text):
    """ Loads a public key from a string """
    public_key = cryptography.hazmat.primitives.serialization.load_pem_public_key(
        bytes(text, 'ascii', errors = 'strict'),
        backend=cryptography.hazmat.backends.default_backend()
    )
    return public_key

def pem(key):
    """ Turn a key (public or private) into PEM format """
    # Private key?
    if hasattr(key, 'decrypt'):
        return key.private_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
            format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()
         )
    # Public key?
    else:
        return key.public_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
            format=cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo
         )


def fingerprint(key):
    """ Derives a digest fingerprint from a key """
    if isinstance(key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
        _pem = pem(key)
    elif type(key) is str:
        _pem = bytes(key, 'ascii', errors = 'replace')
    else:
        _pem = key
    sha = hashlib.sha224(_pem).hexdigest()
    return sha

def decrypt(key, text):
    """ Decrypt a message encrypted with the public key, by using the private key on-disk """
    retval = b""
    i = 0
    txtl = len(text)
    ks = int(key.key_size / 8) # bits -> bytes, room for padding
    # Process the data in chunks the size of the key, as per the encryption
    # model used below.
    while i < txtl:
        chunk = text[i:i+ks]
        i += ks
        ciphertext = key.decrypt(
            chunk,
            cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                    algorithm=cryptography.hazmat.primitives.hashes.SHA1()
                    ),
                algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
                label=None
            )
        )
        retval += ciphertext
    return retval

def encrypt(key, text):
    """ Encrypt a message using the public key, for decryption with the private key """
    retval = b""
    i = 0
    txtl = len(text)
    ks = int(key.key_size / 8) - 64 # bits -> bytes, room for padding
    # Process data in chunks no larger than the key, leave some room for padding.
    while i < txtl:
        chunk = text[i:i+ks-1]
        i += ks
        ciphertext = key.encrypt(
            chunk.encode('utf-8'),
            cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                    algorithm=cryptography.hazmat.primitives.hashes.SHA1()
                    ),
                algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
                label=None
            )
        )
        retval += ciphertext
    return retval


def sign(key, text):
    """ Signs a string with the private key """
    hashver = cryptography.hazmat.primitives.hashes.SHA1()
    hasher = cryptography.hazmat.primitives.hashes.Hash(hashver, cryptography.hazmat.backends.default_backend())
    retval = b""
    i = 0
    txtl = len(text)
    ks = int(key.key_size / 8)
    while i < txtl:
        chunk = text[i:i+ks-1]
        i += ks
        hasher.update(chunk.encode('utf-8'))
    digest = hasher.finalize()
    sig = key.sign(
        digest,
        cryptography.hazmat.primitives.asymmetric.padding.PSS(
            mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(cryptography.hazmat.primitives.hashes.SHA1()),
            salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH
        ),
        cryptography.hazmat.primitives.asymmetric.utils.Prehashed(hashver)
    )
    return sig

def verify(key, sig, text):
    """ Verifies a signature of a text using the public key """
    hashver = cryptography.hazmat.primitives.hashes.SHA1()
    hasher = cryptography.hazmat.primitives.hashes.Hash(hashver, cryptography.hazmat.backends.default_backend())
    retval = b""
    i = 0
    txtl = len(text)
    ks = int(key.key_size / 8)
    while i < txtl:
        chunk = text[i:i+ks-1]
        i += ks
        hasher.update(chunk.encode('utf-8'))
    digest = hasher.finalize()
    try:
        key.verify(
            sig,
            digest,
            cryptography.hazmat.primitives.asymmetric.padding.PSS(
                mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(cryptography.hazmat.primitives.hashes.SHA1()),
                salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH
            ),
            cryptography.hazmat.primitives.asymmetric.utils.Prehashed(hashver)
        )
        return True
    except cryptography.exceptions.InvalidSignature as err:
        return False

def test():
    """ Tests for the crypto lib """
    
    # Generate a key pair, agree on a string to test with
    privkey = keypair()
    pubkey = privkey.public_key()
    mystring = "Bob was here, his burgers were great."
    
    # Test encrypting
    etxt = encrypt(pubkey, mystring)
    
    # Test decrypting
    dtxt = decrypt(privkey, etxt)
    assert(mystring == str(dtxt, 'utf-8'))
    
    # Test signing
    xx = sign(privkey, mystring)
    
    # Test verification
    assert( verify(pubkey, xx, mystring))
    
    print("Crypto lib works as intended!")

