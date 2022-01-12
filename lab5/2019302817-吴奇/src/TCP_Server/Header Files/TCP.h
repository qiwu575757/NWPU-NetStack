#include "Resource.h"

TCPSocket* tcp_socket();
int tcp_bind(TCPSocket* socketid, u_int8_t* server_ip, u_int16_t server_port);
int tcp_close(TCPSocket* socketid);
