#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <string>
#include<vector>
#include<cstdint>

//Protocol constants
const size_t UID_SIZE = 16;
const size_t PUBLIC_KEY_SIZE = 160;
const size_t NAME_SIZE = 255;
const size_t FIXED_REQ_HEADER_SIZE = 23; // fixed request header fields size
const size_t FIXED_RESP_HEADER_SIZE = 7; // fixed response header fields size
const size_t CHUNK_SIZE = 1024;
const int VERSION = 3;
const uint16_t FIXED_ENCRYPTION_PAYLOAD = 267; // fixed sum of values (bytes) in 828 request's payload 

//Request Codes
enum requestCodes {
    REGISTER = 825,
    S_PUBLIC_KEY = 826,
    RECONNECT = 827,
    SEND_FILE = 828,
    VALID_CRC = 900,
    N_VALID_CRC = 901,
    EXIT_CRC = 902 

};
// Response Codes
enum responseCodes{
    REG_SUCCESSFUL  = 1600,
    REG_FAILED = 1601,
    IN_PUBLIC_OUT_CRYPTED = 1602,
    VALID_CRC_FILE = 1603,
    MSG_RECIEVED = 1604,
    OK_RECONN_OUT_AES = 1605,
    RECONNECT_FAILED = 1606,
    GENERAL_ERR = 1607
};

//Paylaod structure
struct payload{
    uint32_t size;
    std::vector<unsigned char> content;
};

//Request packet structure
struct requestPacket{
    char clientID[UID_SIZE];
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
    std::vector<unsigned char> payload;

};

//Response packet structure
struct responsePacket{
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
    std::vector<unsigned char> payload;
};


#endif //PROTOCOL_H