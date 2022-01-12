#include "Ethernet.h"

u_int16_t calculate_check_sum(ip_header* ip_hdr, int len);
void load_ip_header(u_int8_t* ip_buffer, u_int8_t upper_protocol_type);
int is_same_lan(u_int8_t* local_ip, u_int8_t* destination_ip);
/*
send ip packet
call ethernet function to make a complete packet
*/
DWORD WINAPI ip_send(LPVOID pM);//read from the buffer and send it to datalink                                                                       

