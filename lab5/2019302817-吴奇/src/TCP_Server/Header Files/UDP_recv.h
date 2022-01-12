#include "UDP.h"

void udp_recv();
int udp_recvfrom(UDPSocket* socketid, u_int8_t* buf, int buflen, u_int8_t* source_ip, u_int16_t source_port);
void load_data_to_buffer(u_int8_t* target_buffer, u_int8_t* src_data, int len);
