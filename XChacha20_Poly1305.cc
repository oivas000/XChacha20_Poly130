#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

void enterPassword(std::string &password) {
  std::cout << "Enter the password: ";
#ifdef _WIN32
  char ch;
  while ((ch = _getch()) != '\r' && ch != '\n') {
    password.push_back(ch);
    std::cout << '*';
  }
#else
  termios term;
  tcgetattr(STDIN_FILENO, &term);
  term.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &term);
  std::getline(std::cin, password);
  term.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &term);
#endif
  std::cout << std::endl;
}

// Function to derive a key from the password and salt
void deriveKeyFromPassword(unsigned char *key, const std::string &password,
                           const unsigned char *salt) {
  int k = crypto_pwhash(
      key, static_cast<size_t>(crypto_aead_xchacha20poly1305_ietf_KEYBYTES),
      password.c_str(), password.length(), salt,
      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
      crypto_pwhash_ALG_DEFAULT);
  if (k != 0) {
    std::cerr << "Error in deriving key from password" << std::endl;
    throw std::runtime_error("Key derivation failed");
  }
}

// Function to encrypt a file using libsodium
void encryptData(const std::string &inputData, const std::string &outputData,
                 const std::string &password) {
  // Open the input file or stdin
  std::istream *inStream;
  std::ifstream inFile;
  if (inputData == "-") {
    inStream = &std::cin;
  } else {
    inFile.open(inputData, std::ios::binary);
    if (!inFile) {
      std::cerr << "Error opening input file" << std::endl;
      return;
    }
    inStream = &inFile;
  }

  // Open the output file or stdout
  std::ostream *outStream;
  std::ofstream outFile;
  if (outputData == "-") {
    outStream = &std::cout;
  } else {
    outFile.open(outputData, std::ios::binary);
    if (!outFile) {
      std::cerr << "Error opening output file" << std::endl;
      if (inputData != "-") inFile.close();
      return;
    }
    outStream = &outFile;
  }

  // Generate a random salt
  unsigned char salt[crypto_pwhash_SALTBYTES];
  randombytes_buf(salt, sizeof(salt));

  // Derive the key from the password and salt
  unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  deriveKeyFromPassword(key, password, salt);

  // Generate a random nonce
  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  randombytes_buf(nonce, sizeof(nonce));

  // Write the salt and nonce to the output stream
  outStream->write(reinterpret_cast<const char *>(salt), sizeof(salt));
  outStream->write(reinterpret_cast<const char *>(nonce), sizeof(nonce));

// Encrypt the input data in chunks
#ifdef CHUNK_SIZE
  const size_t chunkSize = CHUNK_SIZE * 1024 * 1024;  // CHUNK_SIZE is in MB
#else
  const size_t chunkSize =
      192*1024*1024;  // Adjust the chunk size as per your requirements
#endif
  std::vector<unsigned char> plain(chunkSize);
  std::vector<unsigned char> cipher(chunkSize +
                                    crypto_aead_xchacha20poly1305_ietf_ABYTES);
  while (true) {
    inStream->read(reinterpret_cast<char *>(plain.data()), chunkSize);
    size_t bytesRead = inStream->gcount();
    if (bytesRead <= 0) break;

    unsigned long long cipherLen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(cipher.data(), &cipherLen,
                                               plain.data(), bytesRead, nullptr,
                                               0, nullptr, nonce, key);

    // Write the encrypted chunk to the output stream
    outStream->write(reinterpret_cast<const char *>(cipher.data()), cipherLen);
  }

  // Close the input file or stdin
  if (inputData != "-") inFile.close();

  // Close the output file or stdout
  if (outputData != "-") outFile.close();

  std::clog << "Encrypted successfully" << std::endl;
}

// Function to decrypt a file using libsodium
void decryptData(const std::string &inputData, const std::string &outputData,
                 const std::string &password) {
#ifdef CHUNK_SIZE
  const size_t chunkSize = CHUNK_SIZE * 1024 * 1024;  // CHUNK_SIZE is in MB
#else
  const size_t chunkSize =
      192*1024*1024;  // Adjust the chunk size as per your requirements
#endif
  std::vector<unsigned char> cipher(chunkSize +
                                    crypto_aead_xchacha20poly1305_ietf_ABYTES);
  std::vector<unsigned char> plain(chunkSize);

  // Open the input file
  std::unique_ptr<std::istream> inDataPtr;
  std::ifstream inFile;
  if (inputData == "-") {
    // Read from stdin
    inDataPtr = std::make_unique<std::istream>(std::cin.rdbuf());
  } else {
    // Open the input file
    inFile.open(inputData, std::ios::binary);
    if (!inFile) {
      std::cerr << "Error opening input file" << std::endl;
      return;
    }
    inDataPtr = std::make_unique<std::ifstream>(std::move(inFile));
  }

  std::istream &inData = *inDataPtr;

  // Read the salt
  unsigned char salt[crypto_pwhash_SALTBYTES];
  inData.read(reinterpret_cast<char *>(salt), sizeof(salt));

  // Read the nonce
  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  inData.read(reinterpret_cast<char *>(nonce), sizeof(nonce));

  // Open the output file
  std::unique_ptr<std::ostream> outDataPtr;
  std::ofstream outFile;
  if (outputData == "-") {
    // Write to stdout
    outDataPtr = std::make_unique<std::ostream>(std::cout.rdbuf());
  } else {
    // Open the output file
    outFile.open(outputData, std::ios::binary);
    if (!outFile) {
      std::cerr << "Error opening output file" << std::endl;
      return;
    }
    outDataPtr = std::make_unique<std::ofstream>(std::move(outFile));
  }

  std::ostream &outData = *outDataPtr;

  // Derive the key from the password and salt
  unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  deriveKeyFromPassword(key, password, salt);

  // Decrypt the file in chunks
  while (inData) {
    inData.read(reinterpret_cast<char *>(cipher.data()),
                chunkSize + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    size_t bytesRead = inData.gcount();
    if (bytesRead <= 0) {
      break;
    }

    unsigned long long plainLen;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain.data(), &plainLen, nullptr, cipher.data(), bytesRead, nullptr,
            0, nonce, key) != 0) {
      std::cerr << "Decryption failed" << std::endl;

      // Delete the output file
      if (outputData != "-") std::remove(outputData.c_str());
      return;
    }

    // Write the decrypted chunk to the output file or stdout
    outData.write(reinterpret_cast<const char *>(plain.data()), plainLen);
  }

  std::clog << "Decrypted successfully" << std::endl;
}

int main(int argc, char *argv[]) {
  // Initialize libsodium
  if (sodium_init() < 0) {
    std::cerr << "Error initializing libsodium" << std::endl;
    return 1;
  }

  std::string inData;
  std::string outData;
  std::string password;

  if (argc < 3 || argc > 5) {
    std::cerr << "Created by @oivas000" << std::endl
              << "Using 128mb chunk" << std::endl
              << "Usage: main [-d] <input> <output> [<password>]" << std::endl
              << "'-' can use as STDIN or STDOUT" << std::endl;
    return 1;
  }

  bool isDecrypting = (std::strcmp(argv[1], "-d") == 0);

  if (isDecrypting) {
    inData = argv[2];
    outData = argv[3];
    if (argc == 5) {
      std::ofstream nullStream;
      std::clog.rdbuf(nullStream.rdbuf());
      password = argv[4];
    } else {
      enterPassword(password);
    }
  }

  else {
    inData = argv[1];
    outData = argv[2];
    if (argc == 4) {
      std::ofstream nullStream;
      std::clog.rdbuf(nullStream.rdbuf());
      password = argv[3];
    } else {
      enterPassword(password);
    }
  }

  if (isDecrypting) {
    decryptData(inData, outData, password);
  } else {
#ifdef _WIN32
    if (outData == "-")
      std::cerr << "Encrypted Data can't be STDOUT in Windows." << std::endl;
    else
      encryptData(inData, outData, password);
#else
    encryptData(inData, outData, password);
#endif
  }

  sodium_memzero(const_cast<char *>(password.data()), password.size());
  password.clear();

  return 0;
}
