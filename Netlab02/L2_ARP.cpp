/*
* Author: Tom Mahler
* Date: May 2015
*/
#include "L2_ARP.h"	
#include "NIC.h"
#include <iostream>
#include <vector>
#include <winsock2.h>
using namespace std;

#define PRINT_LOCK pthread_mutex_lock(&NIC::print_mutex)
#define PRINT_UNLOCK pthread_mutex_unlock(&NIC::print_mutex)
#define CACHE_LOCK pthread_mutex_lock(&lock_cache)
#define CACHE_UNLOCK pthread_mutex_unlock(&lock_cache)

struct dataToSend_t
{
	size_t length;
	byte* data;
} typedef dataToSend;

class cell_C
{
public:
	string ip_addr;
	string mac_addr;
	time_t used_last;
	time_t time_last;
	bool mac_is_known;
	int number_sent;
	vector<dataToSend*>* queue_p;

	cell_C(string ip_addr, string mac_addr, bool mac_is_known) : mac_is_known(mac_is_known), ip_addr(ip_addr), mac_addr(mac_addr), number_sent(1), used_last(time(0)), time_last(time(0)) {
		this->queue_p = new vector<dataToSend*>();
	}
};

vector<cell_C*> cache;
pthread_t thread_c;
pthread_mutex_t lock_cache;
bool thread_c_continue = true;


void delCell(cell_C * cell, std::_Vector_iterator<std::_Vector_val<std::_Simple_types<cell_C *>>> &cache_iter);
void resendReq(cell_C * cell, double since_last_t, L2_ARP * l2_arp, const time_t &curr_t);
void printMsg(string msg)
{
	pthread_mutex_lock(&NIC::print_mutex);
	cout << msg << endl;
	pthread_mutex_unlock(&NIC::print_mutex);
}

// Check for needed deletions in cache
void* checkCache(void *arpAsVoid)
{
	L2_ARP* l2_arp = (L2_ARP*)arpAsVoid;
	time_t curr_t;
	cell_C* cell;
	double since_last_t;
	double since_used_t;
	string print_msg;

	while (thread_c_continue)
	{
		Sleep(5000);
		pthread_mutex_lock(&lock_cache);
		for (vector<cell_C*>::iterator cache_iter = cache.begin(); cache_iter != cache.end();) //iterate cache
		{
			curr_t = time(0);
			cell = (*cache_iter);
			since_last_t = difftime(curr_t, cell->time_last);
			since_used_t = difftime(curr_t, cell->used_last);

			if (since_used_t >= 200.0) // Delet if not used in last 200 secs
			{
				print_msg = "IP timout. " + cell->ip_addr + "deleted\n"; // TODO - MAYBE NOT NEEDED
				printMsg(print_msg); // TODO - MAYBE NOT NEEDED
				delCell(cell, cache_iter);
			}

			else // Need to send the request again
			{
				resendReq(cell, since_last_t, l2_arp, curr_t);
				++cache_iter;
			}
		}
		pthread_mutex_unlock(&lock_cache);
	}
	return 0;
}

void resendReq(cell_C * cell, double since_last_t, L2_ARP * l2_arp, const time_t &curr_t)
{
	string print_msg;
	if (!cell->mac_is_known)
	{
		if ((since_last_t >= 1) && (cell->number_sent < 5))
		{
			print_msg = "Resending IP: " + cell->ip_addr + "\n"; // TODO - ,AYBE NO NEEDED
			printMsg(print_msg); // TODO - MAYBE NOT NEEDED
			l2_arp->arprequest(cell->ip_addr);
			cell->number_sent++;
			cell->time_last = curr_t;
		}

		else if (since_last_t >= 20.0)
		{
			print_msg = "Avoiding ARP flooding, Resending IP: " + cell->ip_addr + "\n"; // TODO - MAYBE NOT NEEDED	
			printMsg(print_msg); // TODO - MAYBE NOT NEEDED
			l2_arp->arprequest(cell->ip_addr);
			cell->number_sent = 1;
			cell->time_last = curr_t;
		}
	}
}

void delCell(cell_C * cell, std::_Vector_iterator<std::_Vector_val<std::_Simple_types<cell_C *>>> &cache_iter)
{

	for (vector<dataToSend*>::iterator cell_it = cell->queue_p->begin(); cell_it != cell->queue_p->end(); ++cell_it)
	{
		delete[](*cell_it)->data;
		delete (*cell_it);
	}
	delete (*cache_iter);
	cache_iter = cache.erase(cache_iter);
}


/**
* Implemented for you
*/
L2_ARP::L2_ARP(bool debug) : debug(debug) {
	pthread_mutex_init(&lock_cache, NULL);
	pthread_create(&thread_c, NULL, checkCache, this);
}

L2_ARP::~L2_ARP()
{
	// Wait for cache thread to join and cleanup
	thread_c_continue = false;
	pthread_join(thread_c, NULL);
	pthread_mutex_destroy(&lock_cache);
	for (vector<cell_C*>::iterator cache_iter = cache.begin(); cache_iter != cache.end(); cache_iter++)
	{
		cell_C* cell = (*cache_iter); // TODO - IF NOT GOOD, PROBLEM WITH TYPE
		delCell(cell, cache_iter);
	}
}

/**
* Implemented for you
*/
void L2_ARP::setNIC(NIC* nic) { this->nic = nic; }

int L2_ARP::arprequest(string ip_addr)
{
	word macAddr_asInt[6];
	byte macAddr_asChar[6];
	uint64_t src_MAC_addr;
	byte* req;

	sscanf(nic->myMACAddr.c_str(), "%x:%x:%x:%x:%x:%x", &macAddr_asInt[5], &macAddr_asInt[4], &macAddr_asInt[3], &macAddr_asInt[2], &macAddr_asInt[1], &macAddr_asInt[0]);
	for (int i = 0; i < 6; i++) { 
		macAddr_asChar[i] = (unsigned char)macAddr_asInt[5 - i]; 
	}
	src_MAC_addr = *((uint64_t*)macAddr_asChar);

	/* NOT NEEDED MAYBE ???
	PRINT_LOCK;
	cout << "Sending ARP Packet: " << ip_addr << ", what is your MAC?\n";
	cout << "< ARP(28 bytes) ::" << " , HardwareType = " << 1 << " , ProtocolType = 0x" << std::hex << 0x0800 << std::dec;
	cout << " , HardwareLength = " << (short_word)6 << " , ProtocolLength = " << (short_word)4 << " , SenderMAC = " << nic->myMACAddr;
	cout << " , SenderIP = " << nic->myIP << " , TargetMAC = " << "00:00:00:00:00:00" << " , TargetIP = " << ip_addr << " , >\n\n";
	PRINT_UNLOCK;
	*/

	// Construct and send request
	buildReq(req, src_MAC_addr, ip_addr);
	int result = nic->getUpperInterface()->sendToL2(req, 28, AF_UNSPEC, "00:00:00:00:00:00", 0x0806, ip_addr);
	delete[] req;
	return result;
}

void L2_ARP::buildReq(byte * &req, const uint64_t &src_MAC_addr, std::string &ip_addr)
{
	/* Build request with the following atttributes:
		data size = 46, ar_hrd, Ethertype_IP, hardware length = 6, protocol length = 4, ar_op, source MAC address, source IP address, destination IP address
		*/

	req = new byte[46];
	memset(req, 0, 46);
	*((short_word*)(req)) = htons(1);
	*((short_word*)(req + 2)) = htons(0x0800); 
	*((byte*)(req + 4)) = 6; 
	*((byte*)(req + 5)) = 4; 
	*((short_word*)(req + 6)) = htons(1); 
	*((uint64_t*)(req + 8)) = src_MAC_addr; 
	*((word*)(req + 14)) = inet_addr(nic->myIP.c_str()); 
	*((word*)(req + 24)) = inet_addr(ip_addr.c_str());
}

void pushNewData(dataToSend * &data_to_send, const size_t &sendDataLen, byte * sendData, cell_C * cell)
{
	data_to_send = new dataToSend();
	data_to_send->length = sendDataLen;
	data_to_send->data = new byte[sendDataLen];
	memcpy(data_to_send->data, sendData, sendDataLen);
	cell->queue_p->push_back(data_to_send);
}

string L2_ARP::arpresolve(string ip_addr, byte *sendData, size_t sendDataLen)
{
	if (ip_addr.compare(nic->myIP) == 0 || ip_addr.compare("127.0.0.1") == 0) // If self IP
		return nic->myMACAddr;

	pthread_mutex_lock(&lock_cache);
	string res = "";
	cell_C* cell = (cell_C*)(this->arplookup(ip_addr, false));
	dataToSend* data_to_send;

	if (cell != NULL) // if IP in chache
	{
		if (cell->mac_is_known)  // MAC is known
		{
			res = cell->mac_addr;
			cell->used_last = time(0);
		}
		else // MAC is unknown
		{
			//not recognized - push to waiting packets queue
			pushNewData(data_to_send, sendDataLen, sendData, cell);
		}
	}
	else // IP isn't in cache, create new enrey and make ARP request
	{
		cell = (cell_C*)(this->arplookup(ip_addr, true));
		pushNewData(data_to_send, sendDataLen, sendData, cell);
		cache.push_back(cell);
		arprequest(cell->ip_addr);
	}
	pthread_mutex_unlock(&lock_cache);
	return res;
}


void lookForCell(std::string &ip_addr, cell_C * &cell)
{
	for (vector<cell_C*>::iterator cache_iter = cache.begin(); cache_iter != cache.end(); ++cache_iter) {
		if ((*cache_iter)->ip_addr.compare(ip_addr) == 0)
		{
			cell = *cache_iter;
			break;
		}
	}
}

void* L2_ARP::arplookup(string ip_addr, bool create)
{
	cell_C* cell = NULL;
	if (create) // create new cell
	{ 
		cell = new cell_C(ip_addr, "", false);
	} 
	else  // look for cell
	{
		lookForCell(ip_addr, cell);
	}
	return cell;
}

int L2_ARP::in_arpinput(byte *recvData, size_t recvDataLen)
{
	string print_msg = "ARP packet received!\n"; // TODO - CHECK IF NEEDED
	printMsg(print_msg); // TODO - CHECK IF NEEDED

	//check vaildity
	if (recvDataLen != 46) { PRINT_LOCK; cout << "Wrong size for ARP packet. packet dropped.!\n"; PRINT_UNLOCK; return 0; }

	//read paramaters
	short_word hardware = htons(*((short_word*)recvData));
	short_word protocol = htons(*((short_word*)(recvData + 2)));
	byte hardware_len = *((byte*)(recvData + 4));
	short_word protocol_len = *((byte*)(recvData + 5));
	short_word op = htons(*((short_word*)(recvData + 6)));

	//ip and mac convertion to string
	char buffer[50];
	sprintf(buffer, "%d.%d.%d.%d", (unsigned char)recvData[14], (unsigned char)recvData[15], (unsigned char)recvData[16], (unsigned char)recvData[17]);
	string src_ip = string(buffer);
	sprintf(buffer, "%d.%d.%d.%d", (unsigned char)recvData[24], (unsigned char)recvData[25], (unsigned char)recvData[26], (unsigned char)recvData[27]);
	string dest_ip = string(buffer);
	sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)recvData[8], (unsigned char)recvData[9], (unsigned char)recvData[10], (unsigned char)recvData[11], (unsigned char)recvData[12], (unsigned char)recvData[13]);
	string src_mac = string(buffer);
	sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)recvData[18], (unsigned char)recvData[19], (unsigned char)recvData[20], (unsigned char)recvData[21], (unsigned char)recvData[22], (unsigned char)recvData[23]);
	string dest_mac = string(buffer);

	//print packet info
	PRINT_LOCK;
	cout << "< ARP(28 bytes) ::" << " , HardwareType = " << hardware << " , ProtocolType = 0x" << std::hex << protocol << std::dec;
	cout << " , HardwareLength = " << (int)hardware_len << " , ProtocolLength = " << protocol_len << " , SenderMAC = " << src_mac;
	cout << " , SenderIP = " << src_ip << " , TargetMAC = " << dest_mac << " , TargetIP = " << dest_ip << " , >\n\n";
	PRINT_UNLOCK;

	//check validity
	int result = 0;
	if (hardware != 1 || protocol != 0x0800 || hardware_len != 6 || protocol_len != 4)
	{
		PRINT_LOCK; cout << "ARP parameters invalid. Packet dropped.!\n"; PRINT_UNLOCK; return result;
	}

	//check operation
	if (op != 1 && op != 2)
	{
		PRINT_LOCK; cout << "ARP opreation invalid. Packet dropped.!\n"; PRINT_UNLOCK; return result;
	}

	//get the IP from cache
	if (op == 2) {
		CACHE_LOCK;
		cell_C* cell = (cell_C*)arplookup(src_ip, false);
		if (cell == NULL)
		{	//not found
			PRINT_LOCK; cout << "ARP Packet from another host. IP/MAC pair added to cache.\n"; PRINT_UNLOCK;
			if (src_ip.compare(nic->myIP) != 0 && src_ip.compare("127.0.0.1") != 0) { //make sure it's not me who sent it
				cell = new cell_C(src_ip, src_mac, true);
				cache.push_back(cell);
			}

		}
		else
		{	//found - use time set to 0 and packets need to be sent
			cell->mac_is_known = true;
			cell->mac_addr = src_mac;

			for (vector<dataToSend*>::iterator it = cell->queue_p->begin(); it != cell->queue_p->end(); ++it)
			{
				PRINT_LOCK;	cout << "Packet in waiting queue is about to be sent " << (*((cell->queue_p)->begin()))->data << ".\n"; PRINT_UNLOCK;
				result += nic->getUpperInterface()->sendToL2((*it)->data, (*it)->length, AF_UNSPEC, cell->mac_addr, 0x0800, cell->ip_addr);
				delete[](*it)->data; delete (*it);
			}
			cell->queue_p->clear();
			cell->used_last = time(0);
		}
		CACHE_UNLOCK;
	}

	if (op == 1)
	{	//reply if my ip is the destination
		if (dest_ip.compare(nic->myIP) == 0)
			return *(int*)SendArpReply(src_ip, nic->myIP, src_mac, nic->myMACAddr);
		else
		{	//drop if my ip is not the destination
			PRINT_LOCK; cout << "Host IP is not the destination. Packet dropped.!\n"; PRINT_UNLOCK; return 0;
		}
	}

	return result;
}

void* L2_ARP::SendArpReply(string itaddr, string isaddr, string hw_tgt, string hw_snd)
{
	word mac_int[6];
	byte mac_char[6];
	uint64_t src_mac, dest_mac;

	//convert source and destination MAC to int
	sscanf(hw_tgt.c_str(), "%x:%x:%x:%x:%x:%x", &mac_int[5], &mac_int[4], &mac_int[3], &mac_int[2], &mac_int[1], &mac_int[0]);
	for (int i = 0; i < 6; i++) { mac_char[i] = (unsigned char)mac_int[i]; }
	src_mac = *((uint64_t*)mac_char);
	sscanf(hw_snd.c_str(), "%x:%x:%x:%x:%x:%x", &mac_int[5], &mac_int[4], &mac_int[3], &mac_int[2], &mac_int[1], &mac_int[0]);
	for (int i = 0; i < 6; i++) { mac_char[i] = (unsigned char)mac_int[i]; }
	dest_mac = *((uint64_t*)mac_char);

	//print info of reply packet
	PRINT_LOCK;
	cout << "ARP Reply: this is " << isaddr << "!\n" << "< ARP(28 bytes) ::" << " , HardwareType = " << 1;
	cout << " , ProtocolType = 0x" << std::hex << 0x0800 << std::dec << " , HardwareLength = " << (uint16_t)6;
	cout << " , ProtocolLength = " << (uint16_t)4 << " , SenderMAC = " << hw_tgt << " , SenderIP = " << itaddr;
	cout << " , TargetMAC = " << hw_snd << " , TargetIP = " << isaddr << " , >\n\n";
	PRINT_UNLOCK;

	//reply packet creation
	byte* buffer = new byte[46]; //ARP data size = 46
	memset(buffer, 0, 46);
	*((short_word*)(buffer)) = htons(1); //Hardware type = ar_hrd
	*((short_word*)(buffer + 2)) = htons(0x0800); //Protocol type = Ethertype_IP
	*((byte*)(buffer + 4)) = 6; //Hardware length = 6
	*((byte*)(buffer + 5)) = 4;  //Protocol length = 4
	*((short_word*)(buffer + 6)) = htons(2); //ar_op
	*((uint64_t*)(buffer + 8)) = src_mac; //Source MAC address
	*((word*)(buffer + 14)) = inet_addr(itaddr.c_str()); //Source IP address
	*((uint64_t*)(buffer + 18)) = dest_mac; //Destination MAC address
	*((word*)(buffer + 24)) = inet_addr(isaddr.c_str()); //Destination IP address
	int result = nic->getUpperInterface()->sendToL2(buffer, 46, AF_UNSPEC, hw_tgt, 0x0806, itaddr);
	int* result_p = new int(result);
	delete[] buffer;
	return result_p;
}
