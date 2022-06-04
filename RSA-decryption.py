# RSA decryption with a given cyphertext until the given datablock + seed is given

import hashlib
from hashlib import sha256
import binascii

# given cyphertexts
cyphertext1 = "78766a52455329b486aaa414c3a029834a7e4b6ed87019dce4056f4d8999b137404d9ec4df28da201c9b0bc142deb1d86ff94d83becc"
cyphertext2 = "670b865216dfd0aacd5f7fa8802e704fa82f3fb9c7dbe3eb5a9ec308a1a2288648b15d5cc8ba2f54b245a972aea977932c9c84cf6422"
cyphertext3 = "61d5f2a4298bff3d6ebcd78830fb9181d97235623819eb7c60b92dcdf836a6cf731c60187e72f471c05d1c6eab216c3f6032af3c5370"
cyphertext4 = "3651009d02a0c72b9bc206c57d12277594d9eaad28bb3de5d661670b42f1cfafe688b9674e34d4ad79db898205417086e7e1877b9ef1"
cyphertext5 = "96e51d4675c6be5b14ec0cf2a9e9a9610a99d632723b3f1fcfc6b36806f5d74045f47622817cc35f6ffe9afe29f0aa236cbe12371651"

cyphertext = cyphertext1 # choose cyphertext
print("cyphertext: ", cyphertext)
print("length of cybertext: ", len(cyphertext))

p = (2**206) - 5
print("p: ", p)

q = (2**226) - 5
print("q: ", q)

n = p * q
print("n: ", n)

d_hex = "affe0815" # hex
print("d in hex: ", d_hex)

length_seed = 8 # 8 bytes seed
print("length of seed: ", length_seed)



# MGF Functionalities from wikipedia
def i2osp(integer: int, size: int = 4) -> str:
    return b"".join([chr((integer >> (8 * i)) & 0xFF).encode() for i in reversed(range(size))])

def mgf1(input_str: bytes, length: int, hash_func=hashlib.sha1) -> str:
    # Mask generation function.
    counter = 0
    output = b""
    while len(output) < length:
        C = i2osp(counter, 4)
        output += hash_func(input_str + C).digest()
        counter += 1
    return output[:length]


# Input:
#   String cyphertext = hex cyphertext without "0x" in front
#   String d_hex = hex d without "0x" in front
#   Int n = Mod n
def rsa_decryption(cyphertext, d_hex, n):
    decrypted_data = hex(pow(int(cyphertext, 16), int(d_hex, 16), n))[2:]

    print("len of decrypted data without adding 0's in front: ", len(decrypted_data))

    while(len(decrypted_data) != len(cyphertext)):
        decrypted_data = "0" + decrypted_data
    return decrypted_data


# Input:
#   String oaep_p = hex decrypted oaep_p without "0x" in front
#   Int length_seed = byte length of seed to calculate the masked data block length, ...
def decrypted_todatablock(oaep_p, length_seed):
    length_before_datablock = (2 + length_seed * 2)
    print("\nlength before datablock: ", length_before_datablock)

    length_datablock = len(oaep_p) - length_before_datablock
    print("\nlength of datablock: ", length_datablock)

    msk_seed = (oaep_p[:length_before_datablock])[2:]
    print("\nmasked seed: ", msk_seed)

    msk_datablock = (oaep_p[length_before_datablock:])
    print("\nmasked datablock: ", msk_datablock)

    msk_for_seed = binascii.hexlify(mgf1(bytes.fromhex(str(msk_datablock)), length_seed, sha256)).decode('utf-8')
    print("\nmask for seed: ", msk_for_seed)

    seed = hex(int(msk_seed, 16) ^ int(msk_for_seed, 16))[2:]
    print("\nseed: ", seed)

    msk_for_datablock = binascii.hexlify(mgf1(bytes.fromhex(str(seed)), length_datablock, sha256)).decode('utf-8')
    print("\nmask for datablock: ", msk_for_datablock)

    datablock = hex(int(msk_datablock, 16) ^ int(msk_for_datablock, 16))[2:]
    print("\ndatablock: ", datablock)

    return "00" + seed + datablock

oaep_p = rsa_decryption(cyphertext, d_hex, n)
print("\n\nOAEP(P) / RSA decrypted data: ", oaep_p)
print("length of decrypted data: ", len(oaep_p))
print("\n\n'00' + Seed and Datablock: ", decrypted_todatablock(oaep_p, length_seed))