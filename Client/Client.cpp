#include "Client.h"
/*
* The class manages the operations of the client.
* It interacts with the server through request and response packets structs and wraps client's functions into client's opertations 
*/

// Client constructor
Client::Client() try
    :_ti(),
    version(VERSION),// Initializes version number
    _connectionHandler(&_ti),// Initializes connection handler
    _encryptionHandler(&_rsaKeys),// Initializes encryption handler 
    _requestHandler(&_encryptionHandler, &_ti), // Initializes request handler
    _responesHandler(&_encryptionHandler, &_ti,&_crcValid)// Initializes response handler
{
    std::cout << "--------------------" << "Client: " << _ti.getUserName() << "--------------------\n\n";
    _connectionHandler.setConnection();
    _requestHandler.setPublicKey(_rsaKeys.publicKey);
}
catch (std::exception& e) { std::cerr << "Client error: While creating the server " << e.what()<<"Server is terminated\n"; exit(1); }
    
Client::~Client() {
    std::cout << "--------------------" << "Client: " << _ti.getUserName() << "--------------------\n\n";
}

/*
* Uploading process to the server.
* Handles the entire upload process: 
* For new clients - swapping keys
* For all clients: File encryption and CRC validation
* If the CRC is not valid, the client will 2 more times (a total of 3) the file and will try to revalidate the CRC
*/
void Client::uploadFile() {
    try {
        if (_registeredClient == false) {
            sendAndRecieve(&_requestPacket, &_responsePacket, requestCodes::S_PUBLIC_KEY);
            RESEND_IF_SERVER_ERROR(_responsePacket.code,requestCodes::S_PUBLIC_KEY)
        }
        sendAndRecieve(&_requestPacket, &_responsePacket, requestCodes::SEND_FILE);
        RESEND_IF_SERVER_ERROR(_responsePacket.code, requestCodes::SEND_FILE)
        VALID_CRC(_crcValid);
        sendAndRecieve(&_requestPacket, &_responsePacket, requestCodes::VALID_CRC);
        RESEND_IF_SERVER_ERROR(_responsePacket.code,requestCodes::VALID_CRC)
    }
    catch (const std::exception& e) {
        EXIT;
    }
}

//**************************** Registration & signing in functions ******************************************

/*
* Attempts to sign in as an existing user 
* If the sign in request fails, a new client registration request will be sent to the server
* Otherwise, the client process will continue as usual
*/
bool Client::signIn() {
    //trying to sing in as an existing user
    try {
        sendAndRecieve(&_requestPacket, &_responsePacket, requestCodes::RECONNECT);
        switch (_responsePacket.code) {
            case responseCodes::RECONNECT_FAILED: return registerNewClient();
            case responseCodes::OK_RECONN_OUT_AES: _registeredClient = true; return true;
            default: return false;
        }
    }
    catch(const std::exception& e){
        ABORT_OPERATION;
    }
} 

/* Registers a new client if no existing client information is found.
* If a me.info file exists, it will send a request to sign in as an existing client
* After a successfull new client registration the client gets his UUID from server
*/
bool Client::registerNewClient() {
    try {
      /*  if (std::filesystem::exists("me.info")) {
            std::cout << "Client: me.info file was located, signing in with username: " + _ti.getUserName() + '\n';
            return signIn();
        }
        */
        sendAndRecieve(&_requestPacket, &_responsePacket, requestCodes::REGISTER);
        switch (_responsePacket.code) {
        case responseCodes::REG_SUCCESSFUL: std::memcpy(&_requestPacket.clientID, _responsePacket.payload.data(), UID_SIZE); return true;
        case  responseCodes::REG_FAILED:
            std::cerr << "Fatal Error: " << "Client already registered\n" << "\tUser name: " << _ti.getUserName() + "\n\n"; return false;
        default: std::cout << "Client: Unexpected response code received.\n"; return false;
        }
    }
    catch (const std::exception& e) {
        ABORT_OPERATION;
    }
}
//**************************** Client operations & protocol exceptions ******************************************

/*
* Sends and receives a request and response packet between the client and server
* Each process of sending and recieving includes:
* loading a request packet with essential binary data
* Sending the request packet to the sever via socket
* Recieving response data from the server and loading a response packet with it
* Parsing the response packet and operate accordingly
* Each stage returns true for any protocl defined outcome, and false if a client error occurred
* Each value from the above stages goes in a Macro - THROW_IF_NOT which checks if any client error occurred
* If yes, it throws an exception
* INVALID_CRC macro - skips the recieving and parsing response stages when the latest request packet was req 901
*/
bool Client::sendAndRecieve(requestPacket * _requestPacket, responsePacket * _responsePacket,requestCodes code) {
    THROW_IF_NOT(_requestHandler.requestSelector(_requestPacket, code));
    THROW_IF_NOT(_connectionHandler.sendData(_requestPacket));
    INVALID_CRC(code);//  901 
    THROW_IF_NOT(_connectionHandler.receiveData(_responsePacket));
    THROW_IF_NOT(_responesHandler.responseSelector(_responsePacket, _responsePacket->code));
    return true;
}

/*Resends two more times(a total of 3 times) any 828 request that failed to verify the CRC
* If CRC was validated during this process the entire client process will continue as usual
* otherwise, a suitable message will be printed and the connection will be terminated from the client's side
*/
bool Client::resendEncryptedMessage(){
    for (int i = 0; i < 2 && !_crcValid ; i++) {
        sendAndRecieve(&_requestPacket, &_responsePacket, requestCodes::N_VALID_CRC);
        sendAndRecieve(&_requestPacket, &_responsePacket, requestCodes::SEND_FILE);
    }
    if (_crcValid) return true;
    sendAndRecieve(&_requestPacket, &_responsePacket, requestCodes::EXIT_CRC);
    return false;
}
//Resends two more times (a total of 3 times) any request that the server responded with an error to
bool Client::errorResend(bool requestStatus,requestCodes toDo) {
    for (int i = 0; i < 2; i++) {
        std::cout << "Client: Could not complete request " << toDo << "! Resending request for the server("<< (i + 2)<<")\n";
        sendAndRecieve(&_requestPacket, &_responsePacket, toDo);
    }
    if (_responsePacket.code==responseCodes::GENERAL_ERR) {
        std::cerr <<"Fatal Error : Client could not complete request " << toDo << "!" << " Failed after 3 attempts.\n\n";
        return false;
    }
    return true;
}

//main function
int main(){
    Client c;
    std::cout << "Demo: Trying to register as a new client while this client already registered and uploading a file\n\n";
    c.registerNewClient();     
    c.uploadFile();
    std::cout << "Demo: signing in as an existing client uploading a file after server sent a registration error - client exists \n\n";
    c.signIn();
    c.uploadFile(); 
    return 0;
}