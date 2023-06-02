# XChacha20_Poly1305
**Created by [oivas000](https://github.com/oivas000).**

**XChacha20_Poly130 encryption &amp; decryption in C++ using libsodium**

- Only tested on Linux (Ubuntu) &amp; may not be compatible with Windows OS and others.

## Usage
```
Usage: main [-d] <input> <output> [<password>]
'-' can use as STDIN or STDOUT.
'-d' should be given as 1st argument for decrypting.
password can be given as 4th argument, optional. Else prompt for password.
```

## Building
```
c++ Xchacha20_Poly1305.cc -o Xchacha20_Poly1305 -lsodium -O3
```
