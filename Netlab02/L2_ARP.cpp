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

void L2_ARP::readParams(short_word &hardware, byte * recvData, short_word &protocol, byte &h_len, short_word &p_len, short_word &op)
{
	hardware = htons(*((short_word*)recvData));
	protocol = htons(*((short_word*)(recvData + 2)));
	h_len = *((byte*)(recvData + 4));
	p_len = *((byte*)(recvData + 5));
	op = htons(*((short_word*)(recvData + 6)));
}

void L2_ARP::convertAddr2String(char  buff[50], byte * recvData, std::string &ip_src_addr, std::string &ip_dest_addr, std::string &mac_src_addr, std::string &mac_dest_addr)
{
	sprintf(buff, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)recvData[8], (unsigned char)recvData[9], (unsigned char)recvData[10], (unsigned char)recvData[11], (unsigned char)recvData[12], (unsigned char)recvData[13]);
	mac_src_addr = string(buff);
	sprintf(buff, "%d.%d.%d.%d", (unsigned char)recvData[14], (unsigned char)recvData[15], (unsigned char)recvData[16], (unsigned char)recvData[17]);
	ip_src_addr = string(buff);
	sprintf(buff, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)recvData[18], (unsigned char)recvData[19], (unsigned char)recvData[20], (unsigned char)recvData[21], (unsigned char)recvData[22], (unsigned char)recvData[23]);
	mac_dest_addr = string(buff);
	sprintf(buff, "%d.%d.%d.%d", (unsigned char)recvData[24], (unsigned char)recvData[25], (unsigned char)recvData[26], (unsigned char)recvData[27]);
	ip_dest_addr = string(buff);
}

int L2_ARP::firstOpFunc(std::string &ip_dest_addr, std::string &ip_src_addr, std::string &mac_src_addr, std::string &print_msg)
{
	if (ip_dest_addr.compare(nic->myIP) == 0) // Host IP is destination
	{
		return *(int*)SendArpReply(ip_src_addr, nic->myIP, mac_src_addr, nic->myMACAddr);
	}
	else // Host IP isn't destination
	{	
		print_msg = "Destination is not to host IP, packet dropped.\n";
		printMsg(print_msg);
		return 0;
	}
}

void L2_ARP::secondOpFunc(std::string &ip_src_addr, std::string &print_msg, std::string &mac_src_addr, int &res)
{
	pthread_mutex_lock(&lock_cache);
	cell_C* cell = (cell_C*)arplookup(ip_src_addr, false);
	if (cell == NULL) // Cell not found
	{
		print_msg = "Packet from another host. addind to cache"; // TODO - CHECK IF NEEDED
		printMsg(print_msg);

		if ((ip_src_addr.compare("127.0.0.1")) != 0 && (ip_src_addr.compare(nic->myIP) != 0)) // IP is not host
		{
			cell = new cell_C(ip_src_addr, mac_src_addr, true);
			cache.push_back(cell);
		}
	}
	else // Cell found
	{
		cell->mac_addr = mac_src_addr;
		cell->mac_is_known = true;
		for (vector<dataToSend*>::iterator cell_iter = cell->queue_p->begin(); cell_iter != cell->queue_p->end(); ++cell_iter)
		{
			//print_msg = "Next packet waiting to be sent: " + (*((cell->queue_p)->begin()))->data + ".\n"; // TODO - CHECK IF NEEDED
			//printMsg(print_msg);
			res += nic->getUpperInterface()->sendToL2((*cell_iter)->data, (*cell_iter)->length, AF_UNSPEC, cell->mac_addr, 0x0800, cell->ip_addr);
			delete[](*cell_iter)->data; 
			delete (*cell_iter);
		}
		cell->used_last = time(0);
		cell->queue_p->clear();
	}
	pthread_mutex_unlock(&lock_cache);
}

int L2_ARP::in_arpinput(byte *recvData, size_t recvDataLen)
{
	byte h_len;
	short_word p_len;
	short_word protocol;
	short_word hardware;
	short_word op;
	string mac_src_addr;
	string ip_src_addr;
	string mac_dest_addr;
	string ip_dest_addr;
	char buff[50];
	int res = 0;

	string print_msg = "Received ARP packet.\n"; // TODO - CHECK IF NEEDED
	printMsg(print_msg); // TODO - CHECK IF NEEDED

	if (recvDataLen != 46) { // Check data length 
		print_msg = "Data length invalid, packet dropped.\n";
		printMsg(print_msg);
		return 0;
	}

	// Read parameters
	readParams(hardware, recvData, protocol, h_len, p_len, op);

	// Convert address to strings
	convertAddr2String(buff, recvData, ip_src_addr, ip_dest_addr, mac_src_addr, mac_dest_addr);


	/* TODO - CHECK IF NEEDED

	//print packet info
	PRINT_LOCK;
	cout << "< ARP(28 bytes) ::" << " , HardwareType = " << hardware << " , ProtocolType = 0x" << std::hex << protocol << std::dec;
	cout << " , HardwareLength = " << (int)h_len << " , ProtocolLength = " << p_len << " , SenderMAC = " << mac_src_addr;
	cout << " , SenderIP = " << ip_src_addr << " , TargetMAC = " << mac_dest_addr << " , TargetIP = " << ip_dest_addr << " , >\n\n";
	PRINT_UNLOCK;
	*/


	if ((h_len != 6) || (p_len != 4) || (protocol != 0x0800) || (hardware != 1)) // Check parameters
	{
		print_msg = "Inavlid parameters, packet dropped.\n";
		printMsg(print_msg);
		return res;
	}
	if (op == 1)
	{
		return firstOpFunc(ip_dest_addr, ip_src_addr, mac_src_addr, print_msg);
	}
	else if (op == 2) // IP is in cache 
	{
		secondOpFunc(ip_src_addr, print_msg, mac_src_addr, res);
		return res;
	}
	else // if (op != 1 && op != 2) - Check operation
	{
		print_msg = "Invalid operation, packet dropped.\n";
		printMsg(print_msg);
		return res;
	}
}


void L2_ARP::convertMacAddr(std::string &hw_tgt, word  macAddr_asInt[6], byte  macAddr_asChar[6], uint64_t &mac_src_addr, std::string &hw_snd, uint64_t &mac_dest_addr)
{
	sscanf(hw_snd.c_str(), "%x:%x:%x:%x:%x:%x", &macAddr_asInt[5], &macAddr_asInt[4], &macAddr_asInt[3], &macAddr_asInt[2], &macAddr_asInt[1], &macAddr_asInt[0]);
	for (int i = 0; i < 6; i++)
	{
		macAddr_asChar[i] = (unsigned char)macAddr_asInt[i];
	}
	mac_dest_addr = *((uint64_t*)macAddr_asChar);
	sscanf(hw_tgt.c_str(), "%x:%x:%x:%x:%x:%x", &macAddr_asInt[5], &macAddr_asInt[4], &macAddr_asInt[3], &macAddr_asInt[2], &macAddr_asInt[1], &macAddr_asInt[0]);
	for (int i = 0; i < 6; i++)
	{
		macAddr_asChar[i] = (unsigned char)macAddr_asInt[i];
	}
	mac_src_addr = *((uint64_t*)macAddr_asChar);
}

void L2_ARP::buildReply(byte * &pack_reply, const uint64_t &mac_src_addr, std::string &itaddr, const uint64_t &mac_dest_addr, std::string &isaddr)
{
	/* Build reply with the following attributes:
		data size = 46, ar_hrd, Ethertype_IP, hardware length = 6, protocol length = 4, ar_op, 
		source MAC address, source IP address, destination MAC address, destination IP address
		*/
	pack_reply = new byte[46]; 
	memset(pack_reply, 0, 46);
	*((short_word*)(pack_reply)) = htons(1);
	*((short_word*)(pack_reply + 2)) = htons(0x0800); 
	*((byte*)(pack_reply + 4)) = 6; 
	*((byte*)(pack_reply + 5)) = 4; 
	*((short_word*)(pack_reply + 6)) = htons(2);
	*((uint64_t*)(pack_reply + 8)) = mac_src_addr; 
	*((word*)(pack_reply + 14)) = inet_addr(itaddr.c_str());
	*((uint64_t*)(pack_reply + 18)) = mac_dest_addr;
	*((word*)(pack_reply + 24)) = inet_addr(isaddr.c_str());
}

void* L2_ARP::SendArpReply(string itaddr, string isaddr, string hw_tgt, string hw_snd)
{
	uint64_t mac_src_addr;
	uint64_t mac_dest_addr;
	word macAddr_asInt[6];
	byte macAddr_asChar[6];
	byte* pack_reply;

	// Convert MAC source and destination addresses to int
	convertMacAddr(hw_tgt, macAddr_asInt, macAddr_asChar, mac_src_addr, hw_snd, mac_dest_addr);

	/* TODO - CHECK IF NEEDED

	//print info of reply packet
	PRINT_LOCK;
	cout << "ARP Reply: this is " << isaddr << "!\n" << "< ARP(28 bytes) ::" << " , HardwareType = " << 1;
	cout << " , ProtocolType = 0x" << std::hex << 0x0800 << std::dec << " , HardwareLength = " << (uint16_t)6;
	cout << " , ProtocolLength = " << (uint16_t)4 << " , SenderMAC = " << hw_tgt << " , SenderIP = " << itaddr;
	cout << " , TargetMAC = " << hw_snd << " , TargetIP = " << isaddr << " , >\n\n";
	PRINT_UNLOCK;
	*/

	// Build and send reply packet
	buildReply(pack_reply, mac_src_addr, itaddr, mac_dest_addr, isaddr);
	int result = nic->getUpperInterface()->sendToL2(pack_reply, 46, AF_UNSPEC, hw_tgt, 0x0806, itaddr);
	int* result_p = new int(result);
	delete[] pack_reply;
	return result_p;
}
