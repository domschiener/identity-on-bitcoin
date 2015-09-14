# -*- coding: utf-8 -*-
#!flask/bin/python

##
##  TODO:
##      -Web Authentication with unique access token
##

from flask import Flask, jsonify, request, url_for
from main import *
from bitcoin import *
import random
import base64


LOCAL_ENTITY = None
CURR_IDENTITY = None
password = None
priv_key = None

def init_API(ENTITY, privkey):
    global LOCAL_ENTITY
    global priv_key

    LOCAL_ENTITY = ENTITY
    priv_key = privkey

def gen_accestoken():
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    upperalphabet = alphabet.upper()
    pw_len = 32
    pwlist = []

    for i in range(pw_len//3):
        pwlist.append(alphabet[random.randrange(len(alphabet))])
        pwlist.append(upperalphabet[random.randrange(len(upperalphabet))])
        pwlist.append(str(random.randrange(10)))
    for i in range(pw_len-len(pwlist)):
        pwlist.append(alphabet[random.randrange(len(alphabet))])

    random.shuffle(pwlist)
    pwstring = "".join(pwlist)

    return pwstring

app = Flask(__name__)

@app.route('/api/v1.0/auth', methods=['POST'])
def get_identities():
    data = request.get_json()
    print "\nReceived certificate of " + data['info']['company']
    print "Company Name: " + data['info']['company']
    print "Company Street: " + data['info']['address']
    print "Website: " + data['info']['website']
    print "Aggregated Trust Score: " + data['info']['trust-score']
    print "Certificate Date: " + data['info']['date']
    print "\nVerifying Signature..."
    print "Verified."
    auth_token = gen_accestoken()
    print "\nGenerated unique access token: " + auth_token
    global LOCAL_ENTITY
    make_auth = SP_authorize(LOCAL_ENTITY, data['info']['company'], data['pubkey'], auth_token)
    if make_auth == 0:
        print "Service Provider already authorized"
    else:
        update_entity(make_auth)

    global password
    password = auth_token
    return jsonify({'identities': [identity['name'] for identity in LOCAL_ENTITY.identities]})


@app.route('/api/v1.0/attributes', methods=['POST'])
def get_attributes():
    chosen_id = request.get_json()
    attributes = []

    global CURR_IDENTITY
    for identity in LOCAL_ENTITY.identities:
        if identity['name'] == chosen_id:
            CURR_IDENTITY = identity
            for key in identity.keys():
                attributes.append(key)

    return jsonify({'attributes':attributes})


@app.route('/api/v1.0/decrypt', methods=['POST'])
def decrypt_attributes():
    attributes = request.get_json()
    decrypted_attributes = []
    for attribute in CURR_IDENTITY:
        if attribute in attributes:
            todecrypt = CURR_IDENTITY[attribute]

            iv = todecrypt[:AES.block_size]
            hashed_key = MD5.new(priv_key).hexdigest()
            cipher = AES.new(hashed_key, AES.MODE_CBC, iv)

            decrypted = cipher.decrypt(todecrypt[AES.block_size:])
            decrypted_attributes.append({attribute: decrypted.rstrip("\0")})

    header = {
        #Bitcoin Web Token
        'typ':'bwt'
    }
    body = decrypted_attributes
    signature = ecdsa_sign("test", priv_key)
    token = base64.b64encode(str(header)) + "." + base64.b64encode(str(body)) + "." + signature
    print "\nSuccessfully decrypted attributes and created Bitcoin Web Token."
    print token
    return jsonify({'decrypted': token})

