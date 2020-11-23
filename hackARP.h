#include <iostream>
#include <typeinfo>
#include <bitset>
#include <iomanip>
#include <string.h>
#include <unistd.h> // for sleep() function
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>

void sendARP(pcap_t* pcd, uint8_t arp_packet);

int hackARP(char* device_name, uint8_t* server_ip, uint8_t* victim_ip);
void atoiIP(char* addr, uint8_t* ip);
void printMAC(uint8_t* add, int length);
int getAttackerMAC(uint8_t* attacker_mac, char* device);
void getVictimMAC(uint8_t* victim_ip, uint8_t* victim_mac);
void makeEther(struct ether_header* ether, uint8_t* attacker_mac, uint8_t* victim_mac);
void makeArp(struct ether_arp* arp, uint8_t* server_ip, uint8_t* victim_ip, uint8_t* attacker_mac, uint8_t* victim_mac);
