#include "EncryptionHandler.h"

/*
* This class provides functions to handle RSA encryption and decryption,key generation and AES key decryption.
* The class uses Crypto++ library for all cryptographic operations.
*/

//EncryptionHandler constructor 
EncryptionHandler::EncryptionHandler(rsaKeys* clientKeys) {
    generateKeys();
    privateKey = CryptoPP::RSA::PrivateKey(keys);
    publicKey = CryptoPP::RSA::PublicKey(keys);
    clientKeys->publicKey += toStringPublicKey();
    //clientKeys->privateKey += toStringPrivateKey();
}
EncryptionHandler::~EncryptionHandler() {}

//Generates RSA public key and private key using Crypto++ lib
void EncryptionHandler::generateKeys(){
    keys.GenerateRandomWithKeySize(rnd,RSA_KEY_SIZE);
}
//Saves an encoded private key in Base64 format to a file
bool EncryptionHandler::saveEncodedPrivateKey(){
    if (!std::filesystem::exists("key.priv")) {
        std::ofstream file("key.priv");
        if (!file.is_open()) {
            std::cout << ("Client error: Could not save private key into a file connection is terminated\n");
            return false;
        }

        std::string base64Encoded;
        CryptoPP::StringSource(toStringPrivateKey(), true,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(base64Encoded), false
            )
        );
        file << base64Encoded;
        file.close();
        return true;
    }
    else 
        std::cout << "Client error: Client already has generated RSA keys, can't proceed as new client if key.priv file already exists\n";
    return false;
}
//Converts a private RSA key to a string in DER format
std::string EncryptionHandler::toStringPrivateKey() {
    std::string privateKeyEncoded;
    CryptoPP::StringSink derPrivateKeySink(privateKeyEncoded);
    privateKey.DEREncode(derPrivateKeySink);
    return privateKeyEncoded;
}

//Converts a public RSA key to a string in DER format
std::string EncryptionHandler::toStringPublicKey(){
    std::string encodedPublicKeyString;
    CryptoPP::StringSink derPublicKeySink(encodedPublicKeyString);
    publicKey.DEREncode(derPublicKeySink);
    return encodedPublicKeyString;
}

//Converts the private RSA key to a binary string format
std::string EncryptionHandler::toStringBinPrivateKey() {
    std::string privateKeyString;
    CryptoPP::StringSink privateKeySink(privateKeyString);
    privateKey.Save(privateKeySink);
    return privateKeyString;
}

//Decrypts a given AES key using RSA private key
bool EncryptionHandler::decryptAESKey(const unsigned char* cipher,const size_t size){
    std::string decrypted;
    std::string s = readPrivateRsaKey();
 
        loadPrivateKeyFromBase64(s, &privateKey);
    
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);
    CryptoPP::StringSource ss_cipher(reinterpret_cast<const CryptoPP::byte*>(cipher),size, true, new CryptoPP::PK_DecryptorFilter(rnd, d, new CryptoPP::StringSink(decrypted)));
    if (decrypted.size() != AES_KEY_SIZE) 
        throw std::runtime_error("Decrypted key is in the wrong size. Expected size: " + std::to_string(AES_KEY_SIZE) + ", but got: " + std::to_string(decrypted.size()));

    std::memcpy(_key, decrypted.data(), AES_KEY_SIZE);
    std::cout << "Client: AES key received and decrypted successfully!\n";
    return true;
}

//Reads the RSA private key from a file
std::string EncryptionHandler::readPrivateRsaKey() {
    std::ifstream priv("key.priv");
    std::vector<char> buffer;
    if (!priv.is_open()) {
        throw std::runtime_error("Could not locate key.priv file for AES decryption\n");
    }
    buffer.resize(std::filesystem::file_size("key.priv"));
    if(!priv.read(buffer.data(), std::filesystem::file_size("key.priv")))
        throw std::runtime_error("Error reading file: key.priv");
    return std::string(buffer.begin(), buffer.end());

}

//Encrypts a plaintext message using AES in CBC mode
std::string EncryptionHandler::encryptMsg(const char* plain, unsigned int length){
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };
    CryptoPP::AES::Encryption aesEncryption(_key, AES_KEY_SIZE);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
    std::string cipher;
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
    unsigned int offset = 0;
    while (offset < length) {
        unsigned int chunkSize = std::min(static_cast<unsigned int>(CryptoPP::AES::BLOCKSIZE), length - offset);
        stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain + offset), chunkSize);
        offset += chunkSize;
    }
    stfEncryptor.MessageEnd();
    return cipher;
}
//Converts a hexadecimal string to binary data
std::vector<CryptoPP::byte> EncryptionHandler::hexToBinary(const std::string& hexStr) {
    std::vector<unsigned char> binaryData;
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::string hexChar = hexStr.substr(i, 2);
        CryptoPP::byte byte = static_cast<unsigned char>(strtol(hexChar.c_str(), nullptr, 16));
        binaryData.push_back(byte);
    }
    return binaryData;
}
// Loads an RSA private key from a Base64-encoded string
bool EncryptionHandler::loadPrivateKeyFromBase64(std::string &encodedKey, CryptoPP::RSA::PrivateKey* pubKey) {
    try {
        
        std::string decodedKey;
        CryptoPP::StringSource(encodedKey, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedKey)));
        CryptoPP::ByteQueue queue;
        queue.Put((CryptoPP::byte*)decodedKey.data(), decodedKey.size());
        pubKey->BERDecode(queue);
        return true;  
    }
    catch (const std::exception& e) {
       throw std::runtime_error("Error loading private key: " + std::string(e.what())+'\n');
     
    }
}