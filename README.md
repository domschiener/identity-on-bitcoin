# identity-on-bitcoin

This is a simple demonstration of an identity model as described here http://composui.com/2015/09/08/a-treatise-on-identity-part-2-a-new-identity-model-with-prototype/ . This program allows you to create entities, identities, anchor them into the Bitcoin Blockchain and authorize service providers with access to specific attributes of your identity. You can enroll an entity with either a password, picture, file or a fingerprint of yourself (in case you have a fingerprint scanner setup). All of your identities are stored in the Bitcoin Blockchain (through a transaction with OP_RETURN input).

Goal of this project is it to demonstrate a very early proof of concept for a new identity paradigm. 

## Prerequisites

- https://github.com/isislovecruft/python-gnupg
- https://www.dlitz.net/software/pycrypto/

# TO-DO

- More comprehensive transaction creation by using only the utxo that are necessary 
- Deleting identities or changing attributes of a specific identity
- Revoking access to a service provider
- Publish fingerprint scanner with Raspberry Pi code and tutorial
- Change layering of GUI
- Create web interface (GUI is too ugly)
- More testing
