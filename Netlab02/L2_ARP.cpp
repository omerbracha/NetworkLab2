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

// Check for needed deletions in cache
void* delCacheC(void *arpAsVoid)
{
	L2_ARP* l2_arp = (L2_ARP*)arpAsVoid;

	while (thread_c_continue)
	{
		Sleep(5000); //wait for 5 seconds and check again
		
		CACHE_LOCK;
		for (vector<cell_C*>::iterator cache_iter = cache.begin(); cache_iter != cache.end();) //iterate cache
		{
			time_t curr_t = time(0);
			cell_C* cell = (*cache_iter);
			double since_last_t = difftime(curr_t, cell->time_last);
			double since_used_t = difftime(curr_t, cell->used_last);

			//not used in last 200 seconds - delete it
			if (since_used_t >= 200.0)
			{
				PRINT_LOCK; cout << "ARP entry timeout for IP  '" << cell->ip_addr << "'. Dropped.\n"; PRINT_UNLOCK;
				for (vector<dataToSend*>::iterator cell_it = cell->queue_p->begin(); cell_it != cell->queue_p->end(); ++cell_it)
				{
					delete[](*cell_it)->data;
					delete (*cell_it);
				}
				delete (*cache_iter);
				cache_iter = cache.erase(cache_iter);
			}

			else
			{
				//send the requests again
				if (!cell->mac_is_known)
				{
					if (cell->number_sent < 5 && since_last_t >= 1)
					{
						PRINT_LOCK; cout << "IP " << cell->ip_addr << " send again after 5 seconds.\n";	PRINT_UNLOCK;
						l2_arp->arprequest(cell->ip_addr);
						cell->time_last = curr_t;
						cell->number_sent++;
					}

					else if (since_last_t >= 20.0)
					{
						PRINT_LOCK; cout << "IP " << cell->ip_addr << " flooded for 20 seconds\n";
						cout << "IP " << cell->ip_addr << " send again after 5 seconds.\n"; PRINT_UNLOCK;
						l2_arp->arprequest(cell->ip_addr);
						cell->time_last = curr_t;
						cell->number_sent = 1;
					}
				}
				++cache_iter;
			}
		}
		CACHE_UNLOCK;
	}
	return 0;
}


/**
* Implemented for you
*/
L2_ARP::L2_ARP(bool debug) : debug(debug) { pthread_mutex_init(&lock_cache, NULL); pthread_create(&thread_c, NULL, delCacheC, this); }

L2_ARP::~L2_ARP()
{
	//make the cache thread to stop and wait for it to join
	thread_c_continue = false;
	pthread_join(thread_c, NULL);

	//memory cleanup
	pthread_mutex_destroy(&lock_cache);
	for (vector<cell_C*>::iterator it = cache.begin(); it != cache.end(); it++)
	{
		cell_C cell = *(*it);
		for (vector<dataToSend*>::iterator cell_it = cell.queue_p->begin(); cell_it != cell.queue_p->end(); ++cell_it)
		{
			delete[](*cell_it)->data;
			delete (*cell_it);
		}
		delete (*it);
	}
}

/**
* Implemented for you
*/
void L2_ARP::setNIC(NIC* nic) { this->nic = nic; }

int L2_ARP::arprequest(string ip_addr)
{
	word mac_int[6];
	byte mac_char[6];
	uint64_t src_mac;
	sscanf(nic->myMACAddr.c_str(), "%x:%x:%x:%x:%x:%x", &mac_int[5], &mac_int[4], &mac_int[3], &mac_int[2], &mac_int[1], &mac_int[0]);
	for (int i = 0; i < 6; i++) { mac_char[i] = (unsigned char)mac_int[5 - i]; }
	src_mac = *((uint64_t*)mac_char);

	//print request 
	PRINT_LOCK;
	cout << "Sending ARP Packet: " << ip_addr << ", what is your MAC?\n";
	cout << "< ARP(28 bytes) ::" << " , HardwareType = " << 1 << " , ProtocolType = 0x" << std::hex << 0x0800 << std::dec;
	cout << " , HardwareLength = " << (short_word)6 << " , ProtocolLength = " << (short_word)4 << " , SenderMAC = " << nic->myMACAddr;
	cout << " , SenderIP = " << nic->myIP << " , TargetMAC = " << "00:00:00:00:00:00" << " , TargetIP = " << ip_addr << " , >\n\n";
	PRINT_UNLOCK;

	//build the request
	byte* request = new byte[46]; //ARP data size = 46
	memset(request, 0, 46);
	*((short_word*)(request)) = htons(1); //Hardware type = ar_hrd
	*((short_word*)(request + 2)) = htons(0x0800); //Protocol type = Ethertype_IP
	*((byte*)(request + 4)) = 6; //Hardware length = 6
	*((byte*)(request + 5)) = 4; //Protocol length = 4
	*((short_word*)(request + 6)) = htons(1); //ar_op
	*((uint64_t*)(request + 8)) = src_mac; //Source MAC address
	*((word*)(request + 14)) = inet_addr(nic->myIP.c_str()); //Source IP address
	*((word*)(request + 24)) = inet_addr(ip_addr.c_str()); //Destination IP address

														   //send
	int result = nic->getUpperInterface()->sendToL2(request, 28, AF_UNSPEC, "00:00:00:00:00:00", 0x0806, ip_addr);
	delete[] request;
	return result;
}

string L2_ARP::arpresolve(string ip_addr, byte *sendData, size_t sendDataLen)
{
	//check if given address is my IP
	if (ip_addr.compare(nic->myIP) == 0 || ip_addr.compare("127.0.0.1") == 0)
		return nic->myMACAddr;

	CACHE_LOCK;
	//check if the ip is in the cache
	cell_C* cell = (cell_C*)(this->arplookup(ip_addr, false));
	string result = "";
	if (cell != NULL) //found
	{
		if (!cell->mac_is_known)
		{
			//not recognized - push to waiting packets queue
			dataToSend* d = new dataToSend();
			d->data = new byte[sendDataLen];
			memcpy(d->data, sendData, sendDataLen);
			d->length = sendDataLen;
			cell->queue_p->push_back(d);
		}
		else
		{
			//recognizrd - use time set to 0
			cell->used_last = time(0);
			result = cell->mac_addr;
		}
	}
	else
	{
		//create new entry in the cache
		cell = (cell_C*)(this->arplookup(ip_addr, true));
		//push packet to waiting queue
		dataToSend* d = new dataToSend();
		d->data = new byte[sendDataLen];
		memcpy(d->data, sendData, sendDataLen);
		d->length = sendDataLen;
		cell->queue_p->push_back(d);
		cache.push_back(cell);
		//arp request sending
		arprequest(cell->ip_addr);
	}
	CACHE_UNLOCK;
	return result;
}


void* L2_ARP::arplookup(string ip_addr, bool create)
{
	cell_C* cell = NULL;
	if (!create) { //look up in the table
		for (vector<cell_C*>::iterator it = cache.begin(); it != cache.end(); ++it) {
			if ((*it)->ip_addr.compare(ip_addr) == 0) { cell = *it; break; }
		}
	}

	else {//create new cell
		cell = new cell_C(ip_addr, "", false);
	}

	return cell;
}

int L2_ARP::in_arpinput(byte *recvData, size_t recvDataLen)
{
	PRINT_LOCK; cout << "ARP packet received!\n"; PRINT_UNLOCK;
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



