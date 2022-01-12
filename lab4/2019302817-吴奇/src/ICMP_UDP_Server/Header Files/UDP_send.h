#include "UDP.h"

DWORD WINAPI udp_send(LPVOID pM);
int udp_sendto(UDPSocket* socketid, u_int8_t* buf, int buflen, u_int8_t* dest_ip, u_int16_t dest_port);