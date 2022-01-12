#include "Resource.h"

DWORD WINAPI ipv4_distribute(LPVOID pM);
void load_icmp_data(u_int8_t* ip_buffer);
bool is_accept_icmp();
void icmp_recv();
int is_accept_ip_packet(struct ip_header* ip_hdr);
void update_thebuffer();