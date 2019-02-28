# blockchain_edu_day2

## 問題1~3
$ python txid.py < test1.txt

などとやればテキストの値で実行できます

## 問題4

#### requirements
- [base58](https://github.com/keis/base58)
- [secp256k1](https://github.com/ludbb/secp256k1-py)

#### installation (on OS X)
```
brew install automake pkg-config libtool libffi gmp
pip install base58 secp256k1
```

#### usage
extprivを作るとき
```
python bip32.py <path> <seed>
```
extpubを作るとき
```
python bip32.py <path> <seed> public
```

#### examples
```
python bip32.py m/0H/1/2H/2/1000000000 000102030405060708090a0b0c0d0e0f public
b'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy'
```