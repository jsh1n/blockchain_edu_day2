#!/usr/bin/env python

import hashlib

def change_endian(hexstring):
    pairs = [hexstring[i: i+2] for i in range(0, len(hexstring), 2)]
    return "".join(pairs[::-1])

def double_hash(hexstring):
    byte = bytes.fromhex(hexstring)
    ret = hashlib.sha256(hashlib.sha256(byte).digest()).hexdigest()
    return ret

def get_parents(children):
    if len(children) == 1:
        return children
    elif len(children) % 2 == 1:
        children += [children[-1]]
    pairs = [children[i: i+2] for i in range(0, len(children), 2)]
    concated = ["".join(sublist) for sublist in pairs]
    return get_parents([double_hash(e) for e in concated])

def main():
    N = input()
    inputs = [change_endian(input()) for i in range(int(N))]
    print(change_endian(get_parents(inputs)[0]))
    return

if __name__ == '__main__':
    main()

