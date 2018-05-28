/*
* Author: Tom Mahler
* Date: May 2015
*/

#include "L2.h"
#include "L2_Arp.h"
#include "NIC.h"
#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <string>
#include "L3.h"
#include "L2_ARP.h"

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
	for (size_t i = 6; i < 12; i++)
	{
		sourceMac = sourceMac + std::to_string(recvData[i]) + ":";
	}

	sourceMac.erase(sourceMac.length() - 1, 1); // trim end

	// get dest mac adress:
	for (size_t i = 0; i < 6; i++)
	{
		destMac = destMac + std::to_string(recvData[i]) + ":";
	}
	destMac.erase(destMac.length() - 1, 1); // trim end

	if (debug) {
		printMsg("source MAC address is: " + sourceMac);
		printMsg("dest MAC address is: " + destMac);
	}

	// get user mac ()
	userMac = nic->myMACAddr;
	if (debug) {
		printMsg("user MAC address is: " + userMac);
	}

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
		printMsg("type is: " + printf("%x", type));
	}

	// extract data from msg
	newSize = recvDataLen - E_H_S;
	data = new byte[newSize];
	memcpy(data, recvData + E_H_S, newSize);

	// send to correct part
	if (type == ARP){
		chk = nic->getARP()->in_arpinput(data, newSize);
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
	short_word word_type;
	word macAddr_asInt[6];
	byte macAddr_asChar[6];
	uint64_t dest_MAC_addr;
	char ip_string[32] = { 0 };
	string dest_MAC_addr_asString;
	string print_msg;
	uint64_t src_MAC_addr;
	int data_size;
	byte* data_toSend;
	int res;

	if (family == AF_UNSPEC) {
		word_type = htons(spec_type);

		// MAC address parsing
		parseMACaddrUNSPEC(spec_mac, macAddr_asInt, macAddr_asChar, dest_MAC_addr);
	}

	else { // if (family == AF_INET)
		word_type = htons(0x0800);

		// Extract the IP address from the packet header
		getIP(dst_addr, ip_string, sendData);

		// Extract the gateway IP address
		getGatewayIP(dst_addr);

		// Extract MAC address of the destination
		dest_MAC_addr_asString = nic->getARP()->arpresolve(dst_addr, sendData, sendDataLen);

		// Throw packet if there is no MAC address
		if (dest_MAC_addr_asString.compare("") == 0)
		{
			if (debug)
			{
				print_msg = "Throwing packet - IP address not recognized: " + dst_addr + "\n";
				printMsg(print_msg);
			}
			return 0;
		}

		// MAC address parsing
		parseMACaddrINET(dest_MAC_addr_asString, macAddr_asInt, macAddr_asChar, dest_MAC_addr);
	}

	// Create Ethernet header
	createHeader(macAddr_asInt, macAddr_asChar, src_MAC_addr, data_size, sendDataLen, data_toSend, dest_MAC_addr, word_type, sendData);
	if (debug)
	{
		print_header(print_msg, dest_MAC_addr, src_MAC_addr, word_type);
	}

	// Send data
	res = nic->lestart(data_toSend, data_size);

	delete[] data_toSend;
	if (res != 0) {
		return sendDataLen;
	}
	else return 0;
}

void L2::createHeader(word  macAddr_asInt[6], byte  macAddr_asChar[6], uint64_t &src_MAC_addr, int &data_size, const size_t &sendDataLen, byte * &data_toSend, uint64_t &dest_MAC_addr, short_word &word_type, byte * sendData)
{
	sscanf(nic->myMACAddr.c_str(), "%x:%x:%x:%x:%x:%x", &macAddr_asInt[0], &macAddr_asInt[1], &macAddr_asInt[2], &macAddr_asInt[3], &macAddr_asInt[4], &macAddr_asInt[5]);
	for (int i = 0; i < 6; i++)
	{
		macAddr_asChar[i] = (unsigned char)macAddr_asInt[i];
	}
	src_MAC_addr = *((uint64_t*)macAddr_asChar);
	data_size = 14 + ((sendDataLen < 46) ? 46 : sendDataLen);  //Ethernet Header size = 14, zeros pad if needed
	data_toSend = new byte[data_size];
	memset(data_toSend, 0, data_size);
	memcpy(data_toSend, (byte*)(&dest_MAC_addr), 6); //Destination MAC address
	memcpy(data_toSend + 6, (byte*)(&src_MAC_addr), 6); //Source MAC address
	memcpy(data_toSend + 12, &word_type, 2); //type
	memcpy(data_toSend + 14, sendData, sendDataLen); //data
}

void L2::parseMACaddrUNSPEC(std::string &spec_mac, word  macAddr_asInt[6], byte  macAddr_asChar[6], uint64_t &dest_MAC_addr)
{
	sscanf(spec_mac.c_str(), "%x:%x:%x:%x:%x:%x", &macAddr_asInt[0], &macAddr_asInt[1], &macAddr_asInt[2], &macAddr_asInt[3], &macAddr_asInt[4], &macAddr_asInt[5]);
	for (int i = 0; i < 6; i++)
	{
		macAddr_asChar[i] = (unsigned char)macAddr_asInt[i];
	}
	dest_MAC_addr = *((uint64_t*)macAddr_asChar);
}

void L2::parseMACaddrINET(std::string &dest_MAC_addr_asString, word  macAddr_asInt[6], byte  macAddr_asChar[6], uint64_t &dest_MAC_addr)
{
	sscanf(dest_MAC_addr_asString.c_str(), "%x:%x:%x:%x:%x:%x", &macAddr_asInt[5], &macAddr_asInt[4], &macAddr_asInt[3], &macAddr_asInt[2], &macAddr_asInt[1], &macAddr_asInt[0]);
	for (int i = 0; i < 6; i++)
	{
		macAddr_asChar[i] = (unsigned char)macAddr_asInt[i];
	}
	dest_MAC_addr = *((uint64_t*)macAddr_asChar);
}

void L2::getIP(std::string &dst_addr, char  ip_string[32], byte * sendData)
{
	if (dst_addr.compare("") == 0)
	{
		sprintf(ip_string, "%u.%u.%u.%u", sendData[16], sendData[17], sendData[18], sendData[19]);
		dst_addr = (std::string)ip_string;
	}
}

void L2::getGatewayIP(std::string &dst_addr)
{
	unsigned long and_check_1;
	unsigned long and_check_2;
	and_check_1 = (inet_addr(nic->myIP.c_str()) & inet_addr(nic->myNetmask.c_str()));
	and_check_2 = ((inet_addr(dst_addr.c_str()) & inet_addr(nic->myNetmask.c_str())));
	if ((dst_addr.compare("127.0.0.1") != 0) && (and_check_1 != and_check_2))
		dst_addr = nic->myDefaultGateway;
}

void L2::print_header(std::string &print_msg, uint64_t &destmac, uint64_t &srcmac, short_word &type_word)
{
	print_msg = "Ethernet packet sent (14 bytes). DestinationMAC = ";
	for (int i = 0; i < 6; i++)
	{
		print_msg += "%.2x", ((unsigned char*)(&destmac))[i];
		if (i != 5)
		{
			print_msg += ":";
		}
	}
	print_msg += " SourceMAC = ";
	for (int i = 0; i < 6; i++)
	{
		print_msg += "%.2x", ((unsigned char*)(&srcmac))[i];
		if (i != 5)
		{
			print_msg += ":";
		}
	}
	print_msg += "\n";
	printMsg(print_msg);
}

/**
* Implemented for you
*/
L2::~L2() {}