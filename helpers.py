# -*- coding: utf-8 -*-

import pickle
import time
import os.path
import gnupg
import ast
from bitcoin import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import MD5
from Crypto import Random
from pprint import pprint


#IF YOU HAVE A DIFFERENT LOCAL PGP DIRECTORY, CHANGE IT HERE
gpg = gnupg.GPG(homedir='~/.gnupg', keyring='pubring.gpg', secring='secring.gpg')

  
### 
### Entitiy Class
### 


class entity(object):
    def __init__(self, name, pub_key, pub_addr, auth_method):
        self.name = name
        self.pub_key = pub_key
        self.pub_address = pub_addr
        self.auth_method = auth_method
        self.serviceproviders = []
        self.identities = []
        self.tx_id = None
                
    def gen_sig(self, message, priv_key):
        self.message = message
        self.signature = ecdsa_sign(message, priv_key)
        return self.signature
        
    def proof_sig(self, pub_key):
        return ecdsa_verify(self.message, self.signature, pub_key)
        
    def eternify(self, utxo, priv_key):
        identifier = ''.join(char.encode('hex') for char in self.name)
        hashed_entity = ''.join(char.encode('hex') for char in '[entity]')

        digest = identifier + hashed_entity
        self.tx_id = prepare_tx(self, digest, utxo, priv_key)
        store_entity(self)

        print "Successfully placed your entity in the Blockchain: ", self.tx_id

    def gen_gpg(self, priv_key):
        key_input = gpg.gen_key_input(
            key_type='RSA',
            key_length=2048,
            name_real=self.name,
            name_email=self.name+"@"+self.pub_address,
            passphrase=priv_key)

        key = gpg.gen_key(key_input)
        assert key.fingerprint

        self.gpg_pub = gpg.export_keys(key)
        

### 
### Helper functions for enrolling an entity
### 


def generate_privkey(source):
    priv_key = SHA256.new(source).hexdigest()
    return priv_key


def store_entity(personal_entity):
    entity_stored = open("./entities.txt", 'a')
    pickle.dump(personal_entity, entity_stored)
    entity_stored.close()
    return personal_entity 
 

### 
### Authenticate existing entity
### 


def get_entities():
    list_entities = []
    with open("./entities.txt", "rb") as entity_stored:
        try:
            while True:
                get_entity = pickle.load(entity_stored)
                list_entities.append(get_entity)
        except EOFError:
            pass   

    return list_entities 


def authenticate(auth_secret):
    list_entities = get_entities()
    
    priv_key = SHA256.new(auth_secret).hexdigest()
    pub_key = privtopub(priv_key)

    for entity in list_entities[::-1]:
        if entity.pub_key == pub_key:
            return (entity, priv_key)
        else:
            raise LookupError("Entity not found")
    

### 
### IDENTITY RELATED FUNCTIONS
### 


def pad(s):
    return s + "\0" * (AES.block_size - len(s) % AES.block_size)


def newidentity(entity_obj, identity, tx_input, priv_key):
    identity_obj = encrypt_attributes(identity,priv_key)

    print "Preparing Identity to place in Blockchain"
    pprint(identity_obj)

    identifier = ''.join(char.encode('hex') for char in identity_obj["name"])
    #hashed_identity = SHA1.new(str(identity_obj)).hexdigest()
    hex_identitiy = ''.join(char.encode('hex') for char in '[identity_obj]')
    digest = identifier + hex_identitiy
    
    identity_obj["tx_id"] = prepare_tx(entity_obj, digest, tx_input, priv_key) 

    print "Successfully placed your identity into the Blockchain and stored it locally: " + identity_obj["tx_id"]

    entity_obj.identities.append(identity_obj)
    new_entity = store_entity(entity_obj)
    return (new_entity, identity_obj)


def encrypt_attributes(identity_obj, priv_key):
    hashed_key = MD5.new(priv_key).hexdigest()

    for attribute in identity_obj:
        if attribute != 'name':
            iv = Random.new().read(AES.block_size)
            aes_obj = AES.new(hashed_key, AES.MODE_CBC, iv)

            padded_attribute = pad(identity_obj[attribute])
            identity_obj[attribute] = iv + aes_obj.encrypt(padded_attribute)

    return identity_obj


def decrypt_attributes(ciphertext, priv_key):
    iv = ciphertext[:AES.block_size]
    hashed_key = MD5.new(priv_key).hexdigest()
    cipher = AES.new(hashed_key, AES.MODE_CBC, iv)

    decrypted = cipher.decrypt(ciphertext[AES.block_size:])

    return decrypted.rstrip("\0")

### 
### SERVICE PROVIDER RELATED FUNCTIONS
### 


def SP_authorize(entity, name, gpg_key):
    #importing key into pubring
    import_result = gpg.import_keys(gpg_key)

    gpg_fingerprint = None
    for result in import_result.results:
        gpg_fingerprint = result['fingerprint']

    print
    print "Successfully authorized: " + name
    print
    entity.serviceproviders.append({name:gpg_fingerprint})
    new_entity = store_entity(entity)
    return new_entity


def accesstoken(gpg_fingerprint, identity):
    return gpg.encrypt(identity,gpg_fingerprint)
    

### 
### PUSHING TO THE BLOCKCHAIN
### 

def prepare_tx(entity, digest, utxo, priv_key):
    right_txo = []
    prepared_tx = None
    
    #if UTXO's bigger than twice the tx value, choose largest single UTXO
    if sum([tx['value'] for tx in utxo]) >= (10000 * 2):
        right_txo.append(max(utxo, key=lambda tx:tx['value']))

        if right_txo[0]['value'] > 10000:
            prepared_tx = mktx(right_txo, [{'value': 10000, 'address': entity.pub_address}])
        else:
            right_txo = utxo
            prepared_tx = mktx(right_txo, [{'value': 10000, 'address': entity.pub_address}])
    else:
        if right_txo[0]['value'] > 10000:
            right_txo = utxo
            prepared_tx = mktx(right_txo, [{'value': 10000, 'address': entity.pub_address}])
        else:
            raise ValueError('Not enough funds, you currently have: ' + utxo)

    tx_with_digest = mk_opreturn(digest, prepared_tx)
    signed_tx = sign(tx_with_digest, 0, priv_key)

    #if multiple UTXO's, sign them all
    if len(right_txo) > 1:
        for i in range(1, len(utxo)):
            print priv_key
            signed_tx = sign(signed_tx, i, priv_key)

    return push_blockchain(signed_tx)
            

def push_blockchain(signed_tx):
    try:
        broadcast_tx = pushtx(signed_tx)
    except Exception:
        broadcast_tx = blockr_pushtx(signed_tx)
    tx_list = ast.literal_eval(broadcast_tx)
    return tx_list['data']