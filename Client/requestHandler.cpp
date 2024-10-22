#include "requestHandler.h"


requestHandler::requestHandler( EncryptionHandler *eh,TransferInfo* ti){
    _eh = eh;
    _transferInfo = ti;
    _filename = _transferInfo->getFileName();
}

void requestHandler::setPublicKey(std::string key){ _publicKey = key; }

void requestHandler:: initRequest(requestPacket* requestPacket,requestCodes code,uint32_t length){
    requestPacket->version = boost::endian::native_to_little((uint8_t)(VERSION));
    requestPacket->code = boost::endian::native_to_little((uint16_t)code);
    requestPacket->payloadSize = boost::endian::native_to_little(length);
    requestPacket->payload.clear();
    requestPacket->payload.resize(length);
}

/******************************** Request Functions ********************************
* Each request function prepares a 'requestPacket' struct that will be send by the connection handler class 
* Each function takes care of a single clinet request for the server by 'loading' the relevant data for each request on the struct.
* Each requestPacket struct contains a protocal defined header fields that includes: Client ID,version, request code and payload size.
* Each requestPacket struct contains a payload suitable for it's request.
* Payload size and content varies for each request.
*/

/**
 * Request Code: 825 
 * Handles a new client registration request
 * This function prepares the `requestPacket` to send a registration request to the server.
 * Payload contains: Username
 */
bool requestHandler::registreationRequest(requestPacket* requestPacket){
    char ignore[] = "ignoreignoreign";
    memcpy(requestPacket->clientID,ignore,UID_SIZE);
    initRequest(requestPacket,REGISTER, _transferInfo->getUserName().length() + 1);
    std::memcpy(requestPacket->payload.data(), _transferInfo->getUserName().c_str(), _transferInfo->getUserName().length()+1);//copies binary representation of user name with null char
    std::cout << "Client: Sending a registration request for the server\n";
    return true;     
}

/**
 * Request Code: 826
 * Handles a public key exchange with the server
 * This function prepares the `requestPacket` to send RSA public key and key swapping request to the server.
 * Payload contains: Username,RSA public key.
 */
bool requestHandler::sendPublicKey(requestPacket* requestPacket){
    const size_t len = _transferInfo->getUserName().size();
    std::string pay = _transferInfo->getUserName();
    uint32_t size = pay.length() + _publicKey.length() + 1; //handle it
    initRequest(requestPacket, requestCodes::S_PUBLIC_KEY, size);
    std::memcpy(requestPacket->payload.data(), pay.c_str(), pay.length()+1);
    std::memcpy(requestPacket->payload.data()+ pay.length() + 1, _publicKey.c_str(), _publicKey.length());
    std::cout << "Client: Sending RSA public key to the server\n";
    return true;
}
 
/**
 * Request Code: 828
 * Handles encrypted file uploading request to the server.
 * This function prepares the `requestPacket` to encrypted file's data along with essential file data.
 * Payload contains: Post encryption content size,pre encryption content size,packet number,total packets,
 * file name(padded by the client to 255 chars) and the encrypted file's data.
 */
bool requestHandler::encryptFile(requestPacket* requestPacket) {
    std::pair<uint16_t, uint32_t> origSizeAndPackets;
    std::vector<CryptoPP::byte> encryptedfile;
    std::string path(_transferInfo->getPath());
    uint32_t contentSize = 0;//after enc
    uint32_t origSize = 0;//before enc
    uint16_t currPack = 1;
    uint16_t totalpackets = 0;
    try {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error during file encryption proccess: could not open file in path: "<<path<<"\n";
            return false;
        }
      
        origSizeAndPackets = getFileSizes(file);//throws
        origSize = origSizeAndPackets.second;
        totalpackets = origSizeAndPackets.first;
        getEncryptedData(file, &encryptedfile, origSize);//throws runtime error 
        initRequest(requestPacket, requestCodes::SEND_FILE, FIXED_ENCRYPTION_PAYLOAD + static_cast<uint32_t>(encryptedfile.size()));
        setEncryptionPayload(origSize, currPack, totalpackets, &encryptedfile, requestPacket);
    }
    catch (const std::exception& e) {
        std::cerr << e.what();
        return false;
    }
    std::cout << "Client: Sending encrypted file to the server... Awaiting checksum confirmation\n";

    return true;
}

/**
 * Request Code: 900
 * Handles CRC confirmation.
 * This function prepares the `requestPacket` to notify the server that the CRC computation succeeded and its valid.
 * Payload contains: file name of the successfully CRC check 
 */
bool requestHandler::validCrc(requestPacket* requestPacket) {
    initRequest(requestPacket, requestCodes::VALID_CRC, NAME_SIZE);
    std::memcpy(requestPacket->payload.data(), _filename.data(), NAME_SIZE);
    std::cout << "Client: Checksum verification successful! File integrity confirmed.\n";
    return true;
}

/**
 * Request Code: 901
 * Handles wrong CRC computation.
 * This function prepares the `requestPacket` to notify the server that the CRC computation did not succeed.
 * Request 828 will follow right after
 * Payload contains: file name of the successfully CRC checked computation
 */
bool requestHandler::invalidCrcReSend(requestPacket* requestPacket) {
    initRequest(requestPacket, requestCodes::N_VALID_CRC, NAME_SIZE);
    std::memcpy(requestPacket->payload.data(), _filename.data(), NAME_SIZE);
    std::cerr << "Error: Checksum verification failed! trying to resend the data\n";
    return true;
}
/**
 * Request Code: 902
 * Handles wrong CRC computation abortion.
 * This function prepares the `requestPacket` to notify the server that the CRC computation did not succeed for 3 times and the client will terminate the connection.
 * Payload contains: file name of the successfully CRC checked computation
 */
bool requestHandler::invalidCrcExit(requestPacket* requestPacket) {
    initRequest(requestPacket, requestCodes::EXIT_CRC, NAME_SIZE);
    std::memcpy(requestPacket->payload.data(), _filename.data(), NAME_SIZE);
    std::cerr << "Client: Checksum verification failed for the 3rd time! Sending Termination request.\n";
    return true;
}

/**
 * Request Code: 827
 * Handles existing client sign in.
 * This function prepares the `requestPacket` to notify the server an exsiting client is signing in to the server.
 * Payload contains: Username retrieved from me.info file (padded by the client to 255 chars)
 */
bool requestHandler::clientSignIn(requestPacket* requestPacket) {
    try {
        std::vector<std::string> username_id = getUUIDandUserName(requestPacket);//throws invalid_argument || runtime_error exception
        std::vector<unsigned char> uuid = uuidToBinary(username_id[1]);
        std::string username = username_id[0];
        std::memcpy(requestPacket->clientID, uuid.data(), UID_SIZE);
        initRequest(requestPacket, requestCodes::RECONNECT, static_cast<uint32_t>(username.size()));
        std::memcpy(requestPacket->payload.data(), username.data(), username.size());// me.info file contains username with null char
    }
    catch (const std::exception& e) {
        std::cerr<< e.what() <<std::endl;
        return false;
    }
    std::cout << "Client: Trying to sign in to the server... Awaiting confirmation.\n";
    return true;
}


/******************************** Utils Functions ********************************/

std::vector<unsigned char> requestHandler::uuidToBinary(std::string& hexUUID) {
    //hexUUID is in valid format, getUUIDandUserName func asserted it
    std::vector<unsigned char> binaryData; 
    // Convert hex chars to a byte and add to vector
    for (size_t i = 0; i < hexUUID.length(); i += 2) {
        std::string byteString = hexUUID.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, UID_SIZE));
        binaryData.push_back(byte);
    }
    binaryData.push_back('\0');
    return binaryData;
}
//throws invalid_argument || runtime_error exception
std::vector<std::string> requestHandler::getUUIDandUserName (requestPacket* requestPacket){
    std::ifstream me("me.info");
    std::string UID; std::string username;
    std::vector<std::string> id_name;
    
    if (!me.is_open() || !std::filesystem::exists("me.info")) 
        throw std::runtime_error("Could not use  me.info file for resigning the server.");

    //Reading me file and making sure its valid
    std::getline(me, username);
    if (username.size() > NAME_SIZE)
        throw std::invalid_argument("Invalid user details: Username excceeds it's maximum of 255 chars length, ");
    if (username.empty())
        throw std::invalid_argument("Invalid user details: Could not find username");
    
    std::getline(me, UID);
    if (UID.size() != UID_SIZE * 2 || UID.size() % 2 != 0)//*2 because the private key stored in hex 
        throw std::invalid_argument("Invalid user details: Hex UUID must contain exactly 32 chars this instance conatins " + UID.size());
    username += +'\0';
    id_name.push_back(username);
    id_name.push_back(UID);
    return id_name;
}

// Handles request selection by predefined protocol request codes
bool requestHandler::requestSelector(requestPacket* _requestPacket,requestCodes code){
    switch (code) {
        case(requestCodes::REGISTER): return registreationRequest(_requestPacket);
        case(requestCodes::S_PUBLIC_KEY): return sendPublicKey(_requestPacket);
        case(requestCodes::SEND_FILE): return encryptFile(_requestPacket);
        case(requestCodes::VALID_CRC):return validCrc(_requestPacket);
        case(requestCodes::RECONNECT): return clientSignIn(_requestPacket);
        case(requestCodes::N_VALID_CRC): return invalidCrcReSend(_requestPacket);
        case(requestCodes::EXIT_CRC):return invalidCrcExit(_requestPacket);
        default: 
            return false;
    }
}

/**
* Handles pre encryption analysis needed to build the payload of request 828
* Original size - pre encryption size
* Total packets - how many packets needed for the encrypton blocks
*/
std::pair<uint16_t,uint32_t> requestHandler::getFileSizes(std::ifstream& file) { // throws runtime error
    uint32_t originalSize;
    uint16_t totalpackets;
    std::pair<uint16_t, uint32_t> originalSizeAndPacks;
    file.seekg(0, std::ios::end);
    std::streamsize pos = file.tellg();
    file.seekg(0, std::ios::beg);
    if (pos == -1) {
        throw std::runtime_error("Client: Error totalEncryptedPacket -  could not get file's position ");
    }
    else if (pos > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("Client Error: The total encrypted packet size exceeds the maximum size supported by the server's capabilities.\n");
    }
    originalSize = static_cast<uint32_t>(pos);
    totalpackets = totalEncryptedPacket(originalSize);
    originalSizeAndPacks.first += totalpackets;
    originalSizeAndPacks.second += originalSize;
    return originalSizeAndPacks;
}
// Handles Total packets computation - how many packets needed for the encrypton blocks
uint16_t requestHandler::totalEncryptedPacket(uint32_t origSize) {
    uint16_t totalpackets;
    if (origSize % UID_SIZE == 0) {
        if (origSize / UID_SIZE > std::numeric_limits<uint16_t>::max())
            throw std::runtime_error("Client: Error during file encryption - Total packets number exceeds the max packets allowed\n");
        totalpackets = static_cast<uint16_t>(origSize / UID_SIZE);
    }
    else {
        uint32_t tmp = origSize;
        while (tmp % UID_SIZE)
            tmp++;
        if (tmp / UID_SIZE > std::numeric_limits<uint16_t>::max())
            throw std::runtime_error("Client: Error during file encryption -  Total packets number exceeds the max packets allowed\n");
        totalpackets = static_cast<uint16_t>(tmp / UID_SIZE);
    }
    return totalpackets;
}
//Handles the retrival, encryption and stroage of the desired file
void requestHandler::getEncryptedData(std::ifstream& file, std::vector<CryptoPP::byte>* encryptedfile, uint32_t& origSize) {//throws runtime_error
    std::string encryptedData = "";
    std::vector<char> binaryData;
    binaryData.resize(origSize);
    if (!file.read(binaryData.data(), origSize)) 
        throw std::runtime_error("Error in encryption proccess: could not get file's binary data\n");     
    
    if(binaryData.size()>std::numeric_limits<uint32_t>::max())
        throw std::runtime_error("Error in encryption proccess: File exceeds the maximum file size that the server can handle\n");

    binaryData.push_back('\0');
    encryptedData += _eh->encryptMsg(binaryData.data(), binaryData.size()-1);

    if (encryptedData.size() > std::numeric_limits<uint32_t>::max())
        throw std::runtime_error("Error in encryption proccess: Encrypted File exceeds the maximum file size that the server can handle\n");
    encryptedfile->resize(encryptedData.size());
    std::memcpy(encryptedfile->data(), encryptedData.c_str(), encryptedData.size());
}

/** 
* Builds the payload for request 828
* Payload contains: Post encryption content size,pre encryption content size,packet number,total packets,
 * file name(padded by the client to 255 chars) and the encrypted file's data.
*/
void requestHandler::setEncryptionPayload( uint32_t origSize, uint16_t packetNumber,
    uint16_t totalPackets, std::vector<CryptoPP::byte>* encryptedfile, requestPacket* requestPacket) {
    uint32_t offset = 0;
    _filename = _transferInfo->getFileName();
    boost::endian::store_little_u32(requestPacket->payload.data(), static_cast<uint32_t>(encryptedfile->size()));
    boost::endian::store_little_u32(requestPacket->payload.data() + (offset += sizeof(uint32_t)), origSize);
    boost::endian::store_little_u16(requestPacket->payload.data() + (offset += sizeof(uint32_t)), packetNumber);
    boost::endian::store_little_u16(requestPacket->payload.data() + (offset += sizeof(uint16_t)), totalPackets);
    std::memcpy(requestPacket->payload.data() + (offset += sizeof(uint16_t)), _filename.c_str(), NAME_SIZE);
    std::memcpy(requestPacket->payload.data() + FIXED_ENCRYPTION_PAYLOAD, encryptedfile->data(), encryptedfile->size());
}

