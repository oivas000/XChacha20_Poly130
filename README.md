# XChacha20_Poly1305

**Created by [oivas000](https://github.com/oivas000).**

**XChacha20_Poly130 encryption &amp; decryption in C++ using libsodium**

## Usage

```
Usage: main [-d] <input> <output> [<password>]
'-' can use as STDIN or STDOUT.
'-d' should be given as 1st argument for decrypting.
password can be given as 4th argument, optional. Else prompt for password.
```

## Building

**Flags to compile [Hint]**
```
c++ -fno-rtti -fmerge-all-constants -flto -ffunction-sections -fdata-sections -fomit-frame-pointer \
-O3 -I/path/ -L/path/ -lsodium -static -DCHUNK_SIZE=192 ./XChacha20_Poly1305.cc -o XChacha20_Poly1305
```

## Disclaimer

**This cryptographic code is provided for educational purposes only. Use at your own risk. The author(s) are not liable for any damages arising from its use. Ensure compliance with relevant laws.**