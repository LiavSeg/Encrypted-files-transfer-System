#ifndef CLIENT_H
#define CLIENT_H


#include <iostream>
#include <fstream>
#include <filesystem>
#include "protocol.h"
#include "requestHandler.h"
#include "connectionHandler.h"
#include "ResponseHandler.h"
#include "EncryptionHandler.h"
#include "transferInfo.h"

// Macros to handle exceptions,edge cases in the client process
#define THROW_IF_NOT(status) if ((status)==false) throw std::exception()
#define RESEND_IF_SERVER_ERROR(respCode,toDoCode) if ((respCode) == GENERAL_ERR) { if (errorResend(true,toDoCode)==false) return;}
#define INVALID_CRC(code) if (code== requestCodes::N_VALID_CRC) return true
#define VALID_CRC(crc) if (!(crc)) {if (!(resendEncryptedMessage())) return;}

// Macros to handle errors in the client process
#define EXIT std::cerr << "Client: Due to client error, client terminated its connection\n"; exit(1)
#define ABORT_OPERATION std::cerr << "Client: Due to unexpected client error, client cannot complete its operation\n"; return false

class Client{
    private:
        // Client class variables
        requestHandler _requestHandler;
        connectionHandler _connectionHandler;
        ResponseHandler _responesHandler;
        rsaKeys _rsaKeys;
        requestPacket _requestPacket;
        responsePacket _responsePacket;
        EncryptionHandler _encryptionHandler;
        TransferInfo _ti;
        uint8_t version;

        //Client operations & protocol exceptions & varibles
        bool _crcValid = true;
        bool _registeredClient = false;
        bool sendAndRecieve(requestPacket* _requestPacket, responsePacket* _responsePacket, requestCodes code);
        bool resendEncryptedMessage();
        bool errorResend(bool requestStatus,requestCodes toDo);

    public:
        //Client public operations 
        Client();
        ~Client();
        bool signIn();
        bool registerNewClient();
        void uploadFile();
};
#endif//CLIENT_H 