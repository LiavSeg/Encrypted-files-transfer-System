#include "transferInfo.h"
/*
* This class stores and parses any data that can be found in the transfer.info file
* Username,Port number, Host address and file path
*/

// TransferInfo constructor 
TransferInfo::TransferInfo() : _transferFile("transfer.info"){
    if (!getTransferInfo())
        throw std::exception();
}

// Validates the provided username
bool TransferInfo::isValidUserName(std::string& username) {
    if (username.length()+1 > 100 || username.empty()) {
        std::cout<<"Client Error: During parsign info file - invalid username on transfer file \n";
        return false;
    }
    _userName = username;
    return true;
}


//Retrieves the file name from the specified path in case it's a full path and not just a filename
std::string TransferInfo::getFileName() { // check for errs
    std::filesystem::path p(_path);
    std::string name = p.filename().string();
    //padding file's name with | which is not allowd in windows in file names so after removal (on server's side) the name will be valid
    while (name.length() < NAME_SIZE)
        name += "|";
    return name;
}

// Validates the provided file path
bool TransferInfo::isValidPath(std::string& path) { 
    size_t count = 0;
    if (path.empty()) {
        std::cout<<("Client Error: During parsign info file - path is empty\n");
        return false;
    }

    //removing any trailing blanks
    count = path.size();
    while (count > 0 && isspace(path[count - 1]))
        count--;
    if (count < path.size())
        path = path.substr(0, count);
    _path = path;
    return true;
}

//Reads transfer information from the "transfer.info" file
bool TransferInfo::getTransferInfo() {
    std::ifstream file(_transferFile);
    std::string networkDetails = "";
    std::string userName;
    std::string path = "";

    if (!file.is_open()) {
         std::cout<< "Client Error: During parsign info file - transfer.info file was not found\n";
        return false;
    }
    
    //Extracting and validating host and port number
    if(!std::getline(file, networkDetails) || !setHostPort(networkDetails))
        return false;
   
    if (!std::getline(file, userName) || !isValidUserName(userName))
        return false;
  
    if (!std::getline(file, path) || !isValidPath(path))
        return false;

    return true;
}
//Sets the port and host class variables
bool TransferInfo::setHostPort(std::string &line) {
    if (line.find(':') == std::string::npos) {
        std::cout << "Client Error: During parsign info file - host and port data in a wrong format\n";
        return false;
    }
    size_t token = line.find(':');
    size_t portLength = line.length() - token;//length of port      
    _host = line.substr(0, token);//gets host data
    _port = line.substr(token + 1, portLength);//gets port data
    return true;
}

//returns the path to the file
std::string TransferInfo::getPath() {
    return _path;
}
//Returns the username
std::string TransferInfo::getUserName() {
    return _userName;
}
// Returns the port number
std::string TransferInfo::getPort() {
    return _port;
}
// Returns the host address
std::string TransferInfo::getHost() {
    return _host;
}




