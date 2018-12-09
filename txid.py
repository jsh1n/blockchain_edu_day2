#!/usr/bin/env python

import hashlib

def change_endian(hexstring):
    list = [hexstring[i: i+2] for i in range(0, len(hexstring), 2)]
    return "".join(list[::-1])

def main():
    tx = input()
    bytes_tx = bytes.fromhex(tx)
    ret = change_endian(hashlib.sha256(hashlib.sha256(bytes_tx).digest()).hexdigest())
    print(ret)

if __name__ == '__main__':
    main()

