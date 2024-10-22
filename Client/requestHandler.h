#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H
#include "protocol.h"
#include "EncryptionHandler.h"
#include "transferInfo.h"
#include <fstream>
#include<algorithm>
#include <boost/endian/conversion.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include <utility>

class requestHandler{
    private:
        // requestHandler class variables
        std::string _publicKey;
        std::string _filename;
        EncryptionHandler *_eh;
        TransferInfo* _transferInfo;

        // Request Functions
        void initRequest(requestPacket* requestPacket,requestCodes code, uint32_t length);
        bool registreationRequest(requestPacket* requestPacket);//Request 825
        bool sendPublicKey(requestPacket* requestPacket);//Request 826
        bool clientSignIn(requestPacket* requestPacket);//Request 827
        bool validCrc(requestPacket* requestPacket);//Request 900
        bool invalidCrcReSend(requestPacket* requestPacket);//Request 901
        bool invalidCrcExit(requestPacket* requestPacket);//Request 902

        //Helper functions for request funcitons
        std::pair<uint16_t, uint32_t> getFileSizes(std::ifstream& file);// throws runtime error
        std::vector<unsigned char> uuidToBinary(std::string& hexUUID);
        std::vector<std::string> getUUIDandUserName(requestPacket* requestPacket);//throws invalid_argument || ios_base exception
        void getEncryptedData(std::ifstream& file, std::vector<CryptoPP::byte>* encryptedfile, uint32_t& origSize);//throws runtime error 
        void setEncryptionPayload(uint32_t origSize, uint16_t packetNumber,uint16_t totalPackets,
        std::vector<CryptoPP::byte>* encryptedfile, requestPacket* requestPacket);
        uint16_t totalEncryptedPacket(uint32_t origSize);
        bool encryptFile(requestPacket* requestPacket);

    public:
        //requestHandler public operations 
        requestHandler(EncryptionHandler *eh, TransferInfo* ti);
        bool requestSelector(requestPacket* _requestPacket,requestCodes code);
        void setPublicKey(std::string key);
};
#endif//REQUEST_HANDLER_H
