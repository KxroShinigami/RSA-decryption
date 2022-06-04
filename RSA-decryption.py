# RSA decryption with a given cyphertext until the given datablock + seed is given

import hashlib
from hashlib import sha256
import binascii

# given cyphertexts
cyphertext = [  "78766a52455329b486aaa414c3a029834a7e4b6ed87019dce4056f4d8999b137404d9ec4df28da201c9b0bc142deb1d86ff94d83becc", 
                "670b865216dfd0aacd5f7fa8802e704fa82f3fb9c7dbe3eb5a9ec308a1a2288648b15d5cc8ba2f54b245a972aea977932c9c84cf6422",
                "61d5f2a4298bff3d6ebcd78830fb9181d97235623819eb7c60b92dcdf836a6cf731c60187e72f471c05d1c6eab216c3f6032af3c5370",
                "3651009d02a0c72b9bc206c57d12277594d9eaad28bb3de5d661670b42f1cfafe688b9674e34d4ad79db898205417086e7e1877b9ef1",
                "96e51d4675c6be5b14ec0cf2a9e9a9610a99d632723b3f1fcfc6b36806f5d74045f47622817cc35f6ffe9afe29f0aa236cbe12371651"]


p = (2**206) - 5
print("\np: ", p)

q = (2**226) - 5
print("\nq: ", q)

n = p * q
print("\nn: ", n)

d_hex = "affe0815" # hex
print("\nd in hex: ", d_hex)


# Input:
#   String cyphertext = hex cyphertext without "0x" in front
#   String d_hex = hex d without "0x" in front
#   Int n = Mod n
def rsa_decryption(cyphertext, d_hex, n):
    decrypted_data = hex(pow(int(cyphertext, 16), int(d_hex, 16), n))[2:]

    return decrypted_data

for i in range(4):
    decrypted_data = rsa_decryption(cyphertext[i], d_hex, n)
    print("\n\nOAEP(P) / RSA decrypted data: ", i, " ", cyphertext[i])
    print("OAEP(P) / RSA decrypted data: ", i, " ", decrypted_data)