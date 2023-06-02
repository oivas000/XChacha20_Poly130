#include <sodium.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <termios.h>

void enterPassword(std::string &password)
{
    std::cout << "Enter the password: ";
    termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
    std::getline(std::cin, password);
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
    std::cout << std::endl;
}

// Function to derive a key from the password and salt
void deriveKeyFromPassword(unsigned char *key, const std::string &password, const unsigned char *salt)
{
    int k = crypto_pwhash(key, static_cast<size_t>(crypto_aead_xchacha20poly1305_ietf_KEYBYTES),
                          password.c_str(), password.length(), salt,
                          crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT);
    if (k != 0)
    {
        std::cerr << "Error deriving key from password" << std::endl;
        exit(10);
    }
}

// Function to encrypt a file using libsodium
void encryptData(const std::string &inputData, const std::string &outputData, const std::string &password)
{
    // Read the input file
    std::ifstream inData(inputData, std::ios::binary);
    if (!inData)
    {
        std::cerr << "Error getting input data" << std::endl;
        return;
    }
    std::vector<char> file((std::istreambuf_iterator<char>(inData)), std::istreambuf_iterator<char>());
    inData.close();

    // Generate a random salt
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    // Derive the key from the password and salt
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    deriveKeyFromPassword(key, password, salt);

    // Generate a random nonce
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // Encrypt the file
    std::vector<unsigned char> cipher(file.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long cipherLen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        cipher.data(), &cipherLen,
        reinterpret_cast<const unsigned char *>(file.data()), file.size(),
        nullptr, 0, nullptr, nonce, key);

    // Write the salt, nonce, and cipher to the output file
    std::ofstream outData(outputData, std::ios::binary);
    if (!outData)
    {
        std::cerr << "Error opening output file" << std::endl;
        return;
    }
    outData.write(reinterpret_cast<const char *>(salt), sizeof(salt));
    outData.write(reinterpret_cast<const char *>(nonce), sizeof(nonce));
    outData.write(reinterpret_cast<const char *>(cipher.data()), cipherLen);
    outData.close();

    std::clog << "Encrypted successfully" << std::endl;
}

// Function to decrypt a file using libsodium
void decryptData(const std::string &inputData, const std::string &outputData, const std::string &password)
{
    // Read the input file
    std::ifstream inData(inputData, std::ios::binary);
    if (!inData)
    {
        std::cerr << "Error getting input data" << std::endl;
        return;
    }

    // Read the salt
    unsigned char salt[crypto_pwhash_SALTBYTES];
    inData.read(reinterpret_cast<char *>(salt), sizeof(salt));

    // Read the nonce
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    inData.read(reinterpret_cast<char *>(nonce), sizeof(nonce));

    // Read the cipher
    std::vector<char> cipher((std::istreambuf_iterator<char>(inData)), std::istreambuf_iterator<char>());
    inData.close();

    // Derive the key from the password and salt
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    deriveKeyFromPassword(key, password, salt);

    // Decrypt the cipher
    std::vector<char> decrypted(cipher.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long decryptedLen;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char *>(decrypted.data()), &decryptedLen,
            nullptr,
            reinterpret_cast<unsigned char *>(cipher.data()), cipher.size(),
            nullptr, 0, nonce, key) != 0)
    {
        std::cerr << "Decryption failed" << std::endl;
        return;
    }

    // Write the decrypted data to the output file
    std::ofstream outData(outputData, std::ios::binary);
    if (!outData)
    {
        std::cerr << "Error opening output file" << std::endl;
        return;
    }
    outData.write(decrypted.data(), decryptedLen);
    outData.close();

    std::clog << "Decrypted successfully" << std::endl;
}

int main(int argc, char *argv[])
{
    // Initialize libsodium
    if (sodium_init() < 0)
    {
        std::cerr << "Erroritializing libsodium" << std::endl;
        return 1;
    }
    // /*
    std::string eData;
    std::string dData;
    std::string password;

    if (argc < 3)
    {
        std::cerr << "Created by @oivas000" << std::endl
                  << "Usage: main [-d] <input> <output> [<password>]" << std::endl;
        return 1;
    }

    else if (std::strcmp(argv[1], "-d") == 0)
    {
        eData = argv[2];
        dData = argv[3];
        if (argc == 5)
        {
            std::ofstream nullStream;
            std::clog.rdbuf(nullStream.rdbuf());
            password = argv[4];
            decryptData(eData, dData, password);
        }
        else
        {
            enterPassword(password);
            decryptData(eData, dData, password);
        }
    }
    else
    {
        eData = argv[2];
        dData = argv[1];
        if (argc == 4)
        {
            std::ofstream nullStream;
            std::clog.rdbuf(nullStream.rdbuf());
            password = argv[3];
            encryptData(dData, eData, password);
        }
        else
        {
            enterPassword(password);
            encryptData(dData, eData, password);
        }
    }

    password.clear();

    return 0;
}
