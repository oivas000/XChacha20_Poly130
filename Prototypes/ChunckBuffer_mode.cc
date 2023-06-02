#include <sodium.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <fcntl.h>

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
        std::cerr << "Error in deriving key from password" << std::endl;
        throw std::runtime_error("Key derivation failed");
    }
}

// Function to encrypt a file using libsodium
void encryptData(const std::string &inputData, const std::string &outputData, const std::string &password)
{
    // Open the input file
    int inFile = open(inputData.c_str(), O_RDONLY);
    if (inFile == -1)
    {
        std::cerr << "Error opening input file" << std::endl;
        return;
    }

    // Get the file size
    struct stat st;
    if (fstat(inFile, &st) != 0)
    {
        std::cerr << "Error getting input file size" << std::endl;
        close(inFile);
        return;
    }
    off_t fileSize = st.st_size;

    // Open the output file
    std::ofstream outData(outputData, std::ios::binary);
    if (!outData)
    {
        std::cerr << "Error opening output file" << std::endl;
        close(inFile);
        return;
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

    // Write the salt and nonce to the output file
    outData.write(reinterpret_cast<const char *>(salt), sizeof(salt));
    outData.write(reinterpret_cast<const char *>(nonce), sizeof(nonce));

    // Encrypt the file in chunks
    const size_t chunkSize = 268435456; // Adjust the chunk size as per your requirements
    std::vector<unsigned char> plain(chunkSize);
    std::vector<unsigned char> cipher(chunkSize + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    while (fileSize > 0)
    {
        size_t bytesRead = read(inFile, plain.data(), chunkSize);
        if (bytesRead <= 0)
        {
            std::cerr << "Error reading input file" << std::endl;
            close(inFile);
            outData.close();
            return;
        }

        unsigned long long cipherLen;
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            cipher.data(), &cipherLen,
            plain.data(), bytesRead,
            nullptr, 0, nullptr, nonce, key);

        // Write the encrypted chunk to the output file
        outData.write(reinterpret_cast<const char *>(cipher.data()), cipherLen);

        fileSize -= bytesRead;
    }

    // Close the files
    close(inFile);
    outData.close();

    std::clog << "Encrypted successfully" << std::endl;
}

// Function to decrypt a file using libsodium
void decryptData(const std::string &inputData, const std::string &outputData, const std::string &password)
{
    // Open the input file
    std::ifstream inData(inputData, std::ios::binary);
    if (!inData)
    {
        std::cerr << "Error opening input file" << std::endl;
        return;
    }

    // Read the salt
    unsigned char salt[crypto_pwhash_SALTBYTES];
    inData.read(reinterpret_cast<char *>(salt), sizeof(salt));

    // Read the nonce
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    inData.read(reinterpret_cast<char *>(nonce), sizeof(nonce));

    // Open the output file
    int outFile = open(outputData.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (outFile == -1)
    {
        std::cerr << "Error opening output file" << std::endl;
        inData.close();
        return;
    }

    // Derive the key from the password and salt
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    deriveKeyFromPassword(key, password, salt);

    // Decrypt the file in chunks
    const size_t chunkSize = 268435456; // Adjust the chunk size as per your requirements
    std::vector<unsigned char> cipher(chunkSize + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    std::vector<unsigned char> plain(chunkSize);
    while (inData)
    {
        inData.read(reinterpret_cast<char *>(cipher.data()), chunkSize + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        size_t bytesRead = inData.gcount();
        if (bytesRead <= 0)
        {
            break;
        }

        unsigned long long plainLen;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                plain.data(), &plainLen,
                nullptr,
                cipher.data(), bytesRead,
                nullptr, 0, nonce, key) != 0)
        {
            std::cerr << "Decryption failed" << std::endl;
            inData.close();
            close(outFile);
            remove(outputData.c_str());
            return;
        }

        // Write the decrypted chunk to the output file
        write(outFile, plain.data(), plainLen);
    }

    // Close the files
    inData.close();
    close(outFile);

    std::clog << "Decrypted successfully" << std::endl;
}

int main(int argc, char *argv[])
{
    // Initialize libsodium
    if (sodium_init() < 0)
    {
        std::cerr << "Error initializing libsodium" << std::endl;
        return 1;
    }

    std::string inData;
    std::string outData;
    std::string password;

    if (argc < 3 || argc > 5)
    {
        std::cerr << "Created by @oivas000" << std::endl
                  << "Usage: main [-d] <input> <output> [<password>]" << std::endl;
        return 1;
    }

    bool isDecrypting = false;

    if (std::strcmp(argv[1], "-d") == 0)
    {
        isDecrypting = true;
        if (argc == 5)
        {
            std::ofstream nullStream;
            std::clog.rdbuf(nullStream.rdbuf());
            inData = argv[2];
            outData = argv[3];
            password = argv[4];
        }
        else
        {

            inData = argv[2];
            outData = argv[3];
            enterPassword(password);
        }
    }
    else
    {
        if (argc == 4)
        {
            std::ofstream nullStream;
            std::clog.rdbuf(nullStream.rdbuf());
            inData = argv[1];
            outData = argv[2];
            password = argv[3];
        }
        else
        {

            inData = argv[1];
            outData = argv[2];
            enterPassword(password);
        }
    }

    if (isDecrypting)
    {
        decryptData(inData, outData, password);
    }
    else
    {
        encryptData(inData, outData, password);
    }

    sodium_memzero(const_cast<char *>(password.data()), password.size());
    password.clear();

    return 0;
}
