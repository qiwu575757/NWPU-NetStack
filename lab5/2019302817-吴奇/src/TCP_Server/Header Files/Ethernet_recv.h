#include "Ethernet.h"

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
DWORD WINAPI datalink_receive(LPVOID pM);//create datalink receive the data
DWORD WINAPI datalink_distribute(LPVOID pM);//distribure the data to different buffer