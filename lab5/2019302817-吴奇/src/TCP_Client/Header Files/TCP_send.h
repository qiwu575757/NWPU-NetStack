#include "TCP.h"

int tcp_connect1(TCPSocket* socketid, int send_type);
int tcp_connect2(TCPSocket* socketid, u_int8_t* buf, int buflen, int recvtype);
int tcp_sendto(TCPSocket* socketid, u_int8_t* buf, int have_send_messages, int buflen);
DWORD WINAPI tcp_send(LPVOID pM);
