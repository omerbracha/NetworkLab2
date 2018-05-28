#include "L2.h"
#include "L3.h"
#include "L4.h"
#include <iostream>
#include <winsock2.h>
using namespace std;

#define HEADER_SIZE 20 // in bytes
#define L2_HEADER_SIZE 14 // in bytes
/*
L3 constructor, use it to initiate variables and data structure that you wish to use.
Should remain empty by default (if no global class variables are beeing used).
*/
L3::L3(bool debug){ this->debug = debug; }

/*
sendToL3 is called by the upper layer via the upper layer's L3 pointer.
sendData is the pointer to the data L4 wish to send.
sendDataLen is the length of that data.
srcIP is the machines IP address that L4 supplied.
destIP is the destination IP address that L4 supplied.
debug is to enable print (use true)
*/
int L3::sendToL3(byte *sendData, size_t sendDataLen, std::string srcIP, std::string destIP){
	//
	//     create a new message including a header and data.
	//     we will use the next header stracture, as presented in the instractions : 
	//
	//       0                   1                   2                   3
	//		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//		|Version| IHL   |Type of Service|            Total Length       |
	//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//		| Identification                |Flags|      Fragment Offset    |
	//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//		| Time to Live  | Protocol      |        Header Checksum        |
	//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//		|                           Source Address                      |
	//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//		|                       Destination Address                     |
	//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//		|                   Options                     |    Padding    |
	//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// total new massage size: 
	int newSize = HEADER_SIZE + sendDataLen; // in bytes

	// make a new empty byte* for the new message:
	byte newMessage[65535];

	// fill new byte string with zeros:
	memset(newMessage, 0, newSize);

	// Version - 4 bits
	newMessage[0] = ((byte)4) << 4; // ipv4
	// cout << newMessage[0];
	// IHL - 4 bits 
	newMessage[0] = newMessage[0] + (byte)5;

	// Type of Service - 8 bits 
	// newMessage[1] = zeros
	/* Bits 0 - 2:  Precedence.
	Bit    3 : 0 = Normal Delay
	Bits   4 : 0 = Normal Throughput
	Bits   5 : 0 = Normal Relibility
	Bit  6 - 7 : Reserved for Future Use. */

	// Total Length - 16 bits
	newMessage[2] = (byte)(newSize >> 8);
	newMessage[3] = (byte)(newSize & 0xFF); // masked to take low 8 bits.

	// Identification - 16 bits
	/* An identifying value assigned by the sender to aid in assembling the
	fragments of a datagram. */
	// newMessage[4] = newMessage[5] = zeros.

	// Flags - 3 bits 
	// 0 1 0
	// Bit 0: reserved, must be zero
	// Bit 1 : 1 = Don't Fragment.
	// Bit 2 : (MF)0 = Last Fragment
	newMessage[6] = (byte)0x0;

	// Fragment Offset - 13 bits 
	// newMessage[7] = zeros // no offset

	// Time to Live - 8 bits 
	newMessage[8] = (byte)0xFF; // 255 max

	// Protocol - 8 bits
	newMessage[9] = (byte)1; // ICMP

	// Header Checksum - 16 bits
	// newMessage[10] = later
	// newMessage[11] = later 

	// Source Address - 32 bits 
	// get addr:
	uint32_t tempAddr = inet_addr(srcIP.c_str());
	// cut to bytes ansd reverse:
	newMessage[12] = (byte)(tempAddr & 0xFF);
	tempAddr = tempAddr >> 8;
	newMessage[13] = (byte)(tempAddr & 0xFF);
	tempAddr = tempAddr >> 8;
	newMessage[14] = (byte)(tempAddr & 0xFF);
	tempAddr = tempAddr >> 8;
	newMessage[15] = (byte)(tempAddr & 0xFF);

	//  Destination Address - 32 bit 
	// get addr:
	tempAddr = inet_addr(destIP.c_str());
	// cut to bytes ansd reverse:
	newMessage[16] = (byte)(tempAddr & 0xFF);
	tempAddr = tempAddr >> 8;
	newMessage[17] = (byte)(tempAddr & 0xFF);
	tempAddr = tempAddr >> 8;
	newMessage[18] = (byte)(tempAddr & 0xFF);
	tempAddr = tempAddr >> 8;
	newMessage[19] = (byte)(tempAddr & 0xFF);

	// Options 
	// none

	// Padding
	// none

	// Data
	// copy data to new message, after the header.   
	memcpy(newMessage + HEADER_SIZE, sendData, sendDataLen);

	// Header Checksum 
	uint32_t sum = 0;
	uint16_t tmp = 0;
	for (int i = 0; i < 10; i++)
	{ // sum 16b words
		tmp = (newMessage[i * 2] << 8);
		tmp = tmp + (newMessage[(i * 2) + 1]);
		sum = sum + tmp;
	}

	tmp = (sum >> 16);;
	while (tmp != 0)
	{ // fold until no carry 
		sum = sum & 0x0000FFFF;
		tmp = (sum >> 16);
	}

	// fill
	sum = ~sum;
	newMessage[11] = sum & 0xFF;
	sum = sum >> 8;
	newMessage[10] = sum & 0xFF;

	// send newMessage to 2nd layer:
	int check = lowerInterface->sendToL2(newMessage, newSize, debug);

	return check;
}

/*
recvFromL3 is called by the upper layer via the upper layer's L3 pointer.
recvData is the pointer to the data L4 wish to receive.
recvDataLen is the length of that data.
debug is to enable print (use true)
*/
int L3::recvFromL3(byte *recvData, size_t recvDataLen){
	// total new incomming massage size: 
	int newSize = L2_HEADER_SIZE + recvDataLen; // in bytes

	// make a new empty byte* for the new message:
	byte* newMessage = new byte[newSize];

	// recive from L2:
	
	//int check = lowerInterface->recvFromL2(newMessage, newSize, debug
	int check = 0;


	// check for good recive:
	if (check <= 0){ // bad
		if (debug){  // print
			cout << "bad recive in L3::recvFromL3" << endl;
		}
		delete[] newMessage;	// clear
		return 0;				// fail
	}
	else { // good
		// make sure that packet is whole:
		// Header Checksum 
		uint32_t sum = 0;
		uint16_t tmp = 0;
		for (int i = 0; i < 10; i++)
		{ // sum 16b words
			tmp = (recvData[L2_HEADER_SIZE + (i * 2)] << 8);
			tmp = tmp + (recvData[L2_HEADER_SIZE + (i * 2) + 1]);
			sum = sum + tmp;
		}

		tmp = (sum >> 16);
		while (tmp != 0)
		{ // fold until no carry 
			sum = tmp + (sum & 0x0000FFFF);
			tmp = (sum >> 16);
		}

		sum = ~sum; // 1 comp 
		uint16_t chk = sum; // turn to 16 bit 
		if (chk != 0) {  // bad checksum
			if (debug){  // print
				cout << "bad checksum in recive in L3::recvFromL3" << endl;
			}
			delete[] newMessage;	// clear
			return 0;				// fail
		}
		else if ((recvData[L2_HEADER_SIZE] >> 4) != 4) { // bad version  
			if (debug){  // print
				cout << "bad version in recive in L3::recvFromL3" << endl;
			}
			delete[] newMessage;	// clear
			return 0;				// fail
		}
		else if (!recvData[L2_HEADER_SIZE + 8]) { // bad TTL  
			if (debug){  // print
				cout << "bad TTL in recive in L3::recvFromL3" << endl;
			}
			delete[] newMessage;	// clear
			return 0;				// fail
		}
		else if ((recvData[L2_HEADER_SIZE + 9]) != 1) { // bad protocol  
			if (debug){				// print
				cout << "bad protocol in recive in L3::recvFromL3" << endl;
			}
			delete[] newMessage;	// clear
			return 0;				// fail
		}
		else { // good
			newSize = check - L2_HEADER_SIZE;
			if (newSize <= 0){ // no data
				if (debug){  // print
					cout << "empty data in recive in L3::recvFromL3" << endl;
				}
				delete[] newMessage;	// clear
				return 0;				// fail
			}
			memcpy(newMessage, recvData + L2_HEADER_SIZE, newSize); // copy data to returned byte*. 
		}
	}
	delete[] newMessage;	// clear
	return newSize;			// good
}

/*
Implemented for you
*/
void L3::setLowerInterface(L2* lowerInterface){ this->lowerInterface = lowerInterface; }

/*
Implemented for you
*/
void L3::setUpperInterface(L4* upperInterface){ this->upperInterface = upperInterface; }

/*
Implemented for you
*/
std::string L3::getLowestInterface(){ return lowerInterface->getLowestInterface(); }