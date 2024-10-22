#include "connectionHandler.h"

//connectionHandler constructor
connectionHandler::connectionHandler(TransferInfo* transferInfo):_socket(io_context){
    _transferInfo = transferInfo;
}
//connectionHandler destructor
connectionHandler::~connectionHandler() {stop_sending();}

//Sets the initial connection to the server
bool connectionHandler::setConnection(){ 
    tcp::resolver resolver(io_context);
    try{
        auto endpoints = resolver.resolve(_transferInfo->getHost(), _transferInfo->getPort());
        boost::asio::connect(_socket,endpoints);
    }
    catch (const boost::system::system_error& e){
        throw std::runtime_error("During connection to server " + std::string(e.what()) + "\n\n");
    }
    return true; //successful connection
}
/*Sends a request packet to the server.
* This function prepares a fixed - size header based on the provided requestPacket struct
* and sends it to the server.
* It first loads the header with data using setReqHeaderBinaryData function.
* The function sends the payload of the request packet in chunks using the sendInChunks function.
*/
bool connectionHandler::sendData(requestPacket* requestPacket){
    //Handeling the fixed size fields of the packet
    unsigned char fixedHeader[FIXED_REQ_HEADER_SIZE];
    size_t offset = 0;
    size_t bytes_sent;
    setReqHeaderBinaryData(requestPacket, fixedHeader);
    bytes_sent = boost::asio::write(_socket,boost::asio::buffer(fixedHeader));

    if(bytes_sent!=FIXED_REQ_HEADER_SIZE){
        std::cout << "Incomplete header sent. Expected: " << FIXED_RESP_HEADER_SIZE << ",sent: " << bytes_sent << '\n';
        return false;
    }
    bool sentPayload = sendInChunks(requestPacket->payload);
    if(!sentPayload){
        std::cout << "Failed to send the payload." <<'\n';
        return false;
    }
    return true;
}
/**
 * Sends data in chunks to the server.
 * This function sends data from a client's requestPacket payload in chunks to the socket .
 * The function continues to send until all expected data is sent.
 */
bool connectionHandler::sendInChunks(std::vector<unsigned char> payload){
    size_t size = payload.size();
    size_t toSend = std::min(size,CHUNK_SIZE);
    size_t offest = 0;
    while(size>0){
        size_t bytes_sent = boost::asio::write(_socket,boost::asio::buffer(payload.data()+offest,toSend));
        if (bytes_sent != toSend) {
            std::cerr << "Error: Only " << bytes_sent << " out of " << toSend << " bytes were sent." << '\n';
            return false;
        }
        else if (_error) {
            std::cerr << "Error: " << _error.message() << '\n';
                return false;
        }
        size-=toSend;
        offest+=toSend;
        toSend = std::min(size,CHUNK_SIZE);
    }
    return true;
}
/**
* Receives a complete response packet from the server.
* This function reads a fixed size header and a payload data (in chuks) from the server via.
* It reads the fixed header into a buffer. after receiving the header, it loads the responsePacket struct using the header data.
* It receives the payload data in chunks, adding it to the responsePacket struct.
* If any errors occur during the process, an error message is printed, and the function returns
*/
bool connectionHandler::receiveData(responsePacket* responsePacket){
    unsigned char fixedHeader[FIXED_RESP_HEADER_SIZE];
    size_t receivedHeader;
    size_t receivedPayload;

    try{
        receivedHeader = boost::asio::read(_socket,boost::asio::buffer(fixedHeader, sizeof(fixedHeader)),_error);
        if (receivedHeader != FIXED_RESP_HEADER_SIZE) {
            std::cout << "Incomplete header received. Expected: " << FIXED_RESP_HEADER_SIZE << ",Received: " << receivedHeader << '\n';
            return false;
        }
        setRespHeaderBinaryData(responsePacket,fixedHeader);
        receivedPayload = receiveInChunks(responsePacket);//throws boost::system::system_error
            
        if (!receivedPayload){
            std::cout << "Failed to receive the payload." << std::endl;
            return false;
        }
    }
    catch(const boost::system::system_error& e){
        std::cout<<"Error occured during server's response "<<e.what()<<'\n';
        return false;
    }

    return true;
}

/**
 * Receives data in chunks and loads the payload of the response packet.
 * This function reads data from a socket in chunks to the payload of a given responsePacket struct.
 * The function continues to read until all expected data, as specified by payloadSize
 *
 */
bool connectionHandler::receiveInChunks(responsePacket* responsePacket){
    size_t payloadSize = responsePacket->payloadSize;
    size_t toGet = std::min(CHUNK_SIZE,payloadSize);
    std::vector<char> buffer(toGet);
    responsePacket->payload.clear();
    while (payloadSize>0){
        buffer.resize(toGet);
        size_t receivedBytes = boost::asio::read(_socket,boost::asio::buffer(buffer),_error);
        if(_error){
            throw boost::system::error_code(_error);
        }
        else if(receivedBytes==0&&payloadSize>0){
            return false;
        }
        payloadSize-=toGet;
        toGet = std::min(payloadSize,CHUNK_SIZE);
        responsePacket->payload.insert(responsePacket->payload.end(),buffer.begin(),buffer.end());
        buffer.clear();
    }
    return true;
}

/**
 * Sets the binary data for the response header based on the provided response packet.
 * This function load the `responsePacket struct with data from a provided header array.
 * It extracts the version, code, and payload size from the header in a specific binary format for the given protocol..
 */
void connectionHandler::setRespHeaderBinaryData(responsePacket* responsePacket, unsigned char header[]){
    size_t offset = 0;
    memcpy(&responsePacket->version,header,sizeof(uint8_t));
    responsePacket->code = boost::endian::load_little_u16(header +(offset += sizeof(uint8_t)));
    responsePacket->payloadSize = boost::endian::load_little_u32(header + (offset += sizeof(uint16_t)));
}
/**
 * Sets the binary data for the request header based on the provided request packet.
 * This function loads the binary header array with data from the given requestPacket struct.
 * It copies the client ID, version, code, and payload size into the header in a specific binary format for the given protocol.
 */
void connectionHandler::setReqHeaderBinaryData(requestPacket* requestPacket, unsigned char* header){
    size_t offset = 0;
    std::memcpy(header,requestPacket->clientID,UID_SIZE);//Setting client's id binary data //offset+=UID_SIZE;
    std::memcpy(header + (offset += UID_SIZE), &requestPacket->version, sizeof(uint8_t));//Setting version's binary data //offset+=sizeof(uint8_t);
    std::memcpy(header + (offset += sizeof(uint8_t)), &requestPacket->code, sizeof(uint16_t));//Setting code's binary data //offset+=sizeof(uint16_t);
    std::memcpy(header + (offset += sizeof(uint16_t)), &requestPacket->payloadSize, sizeof(uint32_t));//Setting payload's size binary data
}
//Terminates connection 
void connectionHandler::stop_sending() {
    _socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, _error);
    if (_error) 
          std::cout<<("Client error: While shutting down socket " + _error.message() + "\n\n");
    
    _socket.close(_error);
    if (_error) 
        std::cout << ("Client error: While shutting down socket " + _error.message() + "\n\n");
}