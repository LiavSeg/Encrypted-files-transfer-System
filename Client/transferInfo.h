#ifndef TRANSFER_INFO_H
#define TRANSFER_INFO_H

#include "C:\Users\USER\mmn15\protocol.h"//change it
#include <fstream>
#include <string>
#include <iostream>
#include <filesystem>

class TransferInfo {

private:
	// TransferInfo class variables
	std::string _transferFile;
	std::string _port = "";
	std::string _host = "";
	std::string _path = "";
	std::string _filename = "";
	std::string _userName = "";

	//TransferInfo private operations 
	bool isValidUserName(std::string& username);
	bool isValidPath(std::string& path); 
	bool setHostPort(std::string& line);
	bool getTransferInfo();

public:
	//TransferInfo public operations 
	TransferInfo();
	std::string getPath();
	std::string getUserName();
	std::string getPort();
	std::string getHost();
	std::string getFileName();
};
#endif
