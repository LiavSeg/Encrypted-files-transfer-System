#ifndef CONNECTION_HANDLER_H
#define CONNECTION_HANDLER_H

#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp> 
#include<string>
#include <iostream>
#include "protocol.h"
#include "transferInfo.h"

using boost::asio::ip::tcp;

class connectionHandler{
    private:
        // connectionHandler class variables
        boost::asio::io_context io_context;
        tcp::socket _socket;
        boost::system::error_code _error;
        TransferInfo* _transferInfo;

        //connectionHandler private operations 
        bool sendInChunks(std::vector<unsigned char> payload);//throws boost::system::system_error
        bool receiveInChunks(responsePacket* responsePacket);//throws boost::system::system_error
        void setRespHeaderBinaryData(responsePacket* responsePacket, unsigned char header[]);
        void setReqHeaderBinaryData(requestPacket* requestPacket, unsigned char *header);

    public:
        //connectionHandler public operations 
        connectionHandler(TransferInfo* transferInfo);
        ~connectionHandler();
        void stop_sending();
        bool setConnection();
        bool sendData(requestPacket* requestPacket);
        bool receiveData(responsePacket* responsePacket);
};

#endif
