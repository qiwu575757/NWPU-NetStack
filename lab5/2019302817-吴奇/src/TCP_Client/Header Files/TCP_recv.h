#include "TCP.h"

void tcp_readfrom_ip();
void update_thebuffer5();
int tcp_listen(TCPSocket* socketid, u_int8_t* buf, int buflen);
//将accept()分成了tcp_accept1(),tcp_accept2()，使之更适应接收数据状态机
int tcp_accept1(TCPSocket* socketid, int acklen, int send_type);
int tcp_accept2(TCPSocket* socketid, u_int8_t* buf, int buflen, int send_type);
int tcp_recvfrom(TCPSocket* socketid, u_int8_t* buf, int buflen);
//DWORD WINAPI tcp_recv(LPVOID pM);