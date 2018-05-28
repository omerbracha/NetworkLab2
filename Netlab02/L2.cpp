/*
* Author: Tom Mahler
* Date: May 2015
*/

#include "L2.h"
#include "NIC.h"
#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <string>
using namespace std;

#define E_H_S 14 // ethernet header size
#define ARP 0x806
#define IP 0x800


/**
* Implemented for you
*/
L2::L2(bool debug) : debug(debug){ }

/**
* Implemented for you
*/
void L2::setUpperInterface(L3* upperInterface){ this->upperInterface = upperInterface; }

/**
* Implemented for you
*/
void L2::setNIC(NIC* nic){ this->nic = nic; }

/**
* Implemented for you
*/
NIC* L2::getNIC(){ return nic; }

/**
* Implemented for you
*/
std::string L2::getLowestInterface(){ return nic->getLowestInterface(); }

/*
* a generic print function, imlemented for better readabiltty
*/
void L2::printMsg(string msg)
{
	pthread_mutex_lock(&NIC::print_mutex);
	cout << msg << endl;
	pthread_mutex_unlock(&NIC::print_mutex);
}

/*
* function to turn int to hex. referance to: https://stackoverflow.com/questions/5100718/integer-to-hex-string-in-c
*/

template< typename T >
std::string int_to_hex(T i)
{
	std::stringstream stream;
	stream << "0x"
		<< std::setfill('0') << std::setw(sizeof(T) * 2)
		<< std::hex << i;
	return stream.str();
}

int L2::recvFromL2(byte *recvData, size_t recvDataLen)
{
	string sourceMac = "";		// source mac address
	string destMac = "";		// dest mac address
	string userMac = "";		// user mac
	string tmp = "";			// temp string
	//NIC nic = L2::getNIC();		// get NIC 
	word type = 0x0;			// mesage type
	int newSize = 0;			// extracted data size
	byte* data;					// extraced data
	int chk = 0;				// check called functions success

	//start handeling header: 
	if (debug) {
		printMsg("recived Msg from L2:");	
	}

	// get source mac adress:
	for (size_t i = 0; i < 6; i++)
	{
		sourceMac = sourceMac + std::to_string( recvData[i] ) + ":" ;
	}
	sourceMac.erase(-1,1); // trim end
	
	// get dest mac adress:
	for (size_t i = 6; i < 12; i++)
	{
		destMac = destMac + std::to_string( recvData[i] ) + ":";
	}
	destMac.erase(-1,1); // trim end 
	
	if (debug) {
		printMsg("source MAC address is: " + sourceMac);
		printMsg("dest MAC address is: " + destMac);
	}

	// get user mac ()
	userMac = nic->myMACAddr;
	
	if (debug) {
		printMsg("user MAC address is: " + userMac);
	}
	
	printMsg("debug - bolet to compere first numbers, see the HEX vs DEC");
	
	// check if it's not to the user
	if (userMac.compare(destMac) != 0){
		if (debug){
			printMsg("msg not to user. not continued.");
		}
		return 0;
	}

	// check if it's from the user:
	if (userMac.compare(sourceMac) == 0){
		if (debug){
			printMsg("msg originated by user. not continued.");
		}
		return 0;
	}

	// get msg type
	type = type + recvData[12]; // upper
	type = type << 8; 
	type = type + recvData[13]; // lower
	
	if (debug){
		printMsg("type is: " + int_to_hex(type));
	}

	// extract data from msg
	newSize = recvDataLen - E_H_S;
	data = new byte[newSize];
	memcpy(data, recvData + E_H_S, newSize);

	// send to correct part
	if (type == ARP){
		chk = nic->getARP()->inarpinput(data, newSize);
	}
	else if (type == IP){
		chk = upperInterface->recvFromL3(data, newSize);
	}
	else {
		if (debug){
			printMsg("type is not supported.");
		}
	}

	// clear
	delete[] data;
	// 0 in success.
	return chk;
}

int L2::sendToL2(byte *sendData, size_t sendDataLen, uint16_t family, string spec_mac, uint16_t spec_type, string dst_addr)
{
	
}

/**
* Implemented for you
*/
L2::~L2() {}