#!/usr/bin/env python

import hashlib

def double_hash(hexstring):
    byte = bytes.fromhex(hexstring)
    ret = change_endian(hashlib.sha256(hashlib.sha256(byte).digest()).hexdigest())
    return ret

def change_endian(hexstring):
    list = [hexstring[i: i+2] for i in range(0, len(hexstring), 2)]
    return "".join(list[::-1])

def main():
    blockheader = input()
    nonce = 0
    while True:
        blockheader = blockheader[:-8] + change_endian(hex(nonce)[2:].zfill(8))
        blockhash = double_hash(blockheader)
        if blockhash[:4] == "0000":
            break
        nonce += 1
    print(nonce)
    print(blockhash)

if __name__ == '__main__':
    main()
