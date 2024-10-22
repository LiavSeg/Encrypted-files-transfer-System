#ifndef RESPONSE_HANDLER_H
#define RESPONSE_HANDLER_H
#include<iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <type_traits>
#include "protocol.h"
#include "EncryptionHandler.h"
#include "cksum_new.h"
#include "transferInfo.h"

class ResponseHandler{
    private:
        // ResponseHandler class variables
        std::string privateKey;
        EncryptionHandler* eh;
        TransferInfo * _transferInfo;
        bool* _validCrc;
        //ResponseHandler private operations 
        bool createNewClientFile(std::vector<unsigned char> payload);
        bool recieveAesKey(std::vector<unsigned char> payload);
        bool checkSum(std::vector<unsigned char>& payload);
        bool endMessage();
        std::string toHex(const std::vector<unsigned char>& payload);

public:
    //ResponseHandler private operations 
    ResponseHandler(EncryptionHandler* eh, TransferInfo* ti, bool* validCrc);
    bool responseSelector(responsePacket* responsePacket, uint16_t code);
};
#endif
