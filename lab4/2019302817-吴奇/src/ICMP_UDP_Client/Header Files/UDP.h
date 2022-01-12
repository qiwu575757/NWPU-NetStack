#include "Resource.h"

UDPSocket* udp_socket();
int bind(UDPSocket* socketid, u_int8_t* server_ip, u_int16_t server_port);
int udp_close(UDPSocket* socketid);
