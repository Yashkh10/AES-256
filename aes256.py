from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes



def encrypt(plain_text, password):   #encryption

    salt = get_random_bytes(AES.block_size)


    private_key = hashlib.scrypt(

        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)




    cipher_config = AES.new(private_key, AES.MODE_GCM)



    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))

    return {

        'cipher_text': b64encode(cipher_text).decode('utf-8'),

        'salt': b64encode(salt).decode('utf-8'),

        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),

        'tag': b64encode(tag).decode('utf-8')

    }





def decrypt(enc_dict, password):    #decryption

    salt = b64decode(enc_dict['salt'])

    cipher_text = b64decode(enc_dict['cipher_text'])

    nonce = b64decode(enc_dict['nonce'])

    tag = b64decode(enc_dict['tag'])

    



    # generate the private key from the password and salt

    private_key = hashlib.scrypt(

        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)



    # create the cipher config

    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)



    # decrypt the cipher text

    decrypted = cipher.decrypt_and_verify(cipher_text, tag)



    return decrypted





def main():

    password = input("Password: ")



    # First let us encrypt secret message

    encrypted = encrypt("The secretest message here", password)

    print(encrypted)



    # Let us decrypt using our original password

    decrypted = decrypt(encrypted, password)

    print(bytes.decode(decrypted))



main()
