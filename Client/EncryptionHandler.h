#ifndef ENCRYPTION_HANDLER_H
#define ENCRYPTION_HANDLER_H

#include <iostream>
#include <fstream>
#include <filesystem>
#include <cryptopp/rsa.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <immintrin.h>	
#include <cstdint>  

const unsigned int AES_KEY_SIZE = 32;
const size_t RSA_KEY_SIZE = 1024;

struct rsaKeys {
    std::string publicKey = "";
    std::string privateKey = "";
};

class EncryptionHandler{    
    // EncryptionHandler class variables
    CryptoPP::byte _key[AES_KEY_SIZE];
    CryptoPP::InvertibleRSAFunction keys;
    CryptoPP::RSA::PublicKey publicKey;
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::AutoSeededRandomPool rnd;

    //EncryptionHandler private operations 
    std::string stringEncodedPrivate;
    std::string stringPublic;
    void generateKeys();
    std::string toStringPublicKey();
    std::string toStringPrivateKey();
    std::string toStringBinPrivateKey();
    std::string readPrivateRsaKey();
    std::vector<unsigned char> hexToBinary(const std::string& hexStr);
    bool loadPrivateKeyFromBase64(std::string& , CryptoPP::RSA::PrivateKey*);

    public:
        //EncryptionHandler public operations 
        std::string encryptMsg(const char* plain, unsigned int length);
        EncryptionHandler(rsaKeys* keys);
        ~EncryptionHandler();
        bool decryptAESKey(const unsigned char* cipher, const size_t size);
        bool saveEncodedPrivateKey();




};
#endif