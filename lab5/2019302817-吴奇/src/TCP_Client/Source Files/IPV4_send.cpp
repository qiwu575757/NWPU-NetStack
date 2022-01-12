#include "IPV4_send.h"
#include "ARP_Cache_Table.h"
#include "ARP_send.h"
#include "ARP_recv.h"

u_int16_t ip_packet_id = 0;//as flag in ip_header->id
u_int32_t ip_size_of_packet = 0;
extern bool send_endflag;
extern bool arprecv_flag;

extern int ethernet_upper_len;
extern u_int8_t broadcast_mac[6];
extern u_int8_t local_ip[4];
extern u_int8_t target_ip[4];
extern u_int8_t netmask[4];
extern u_int8_t gateway_ip[4];
extern pcap_t* handle;
extern u_int8_t local_mac[6];
extern std::mutex sendlock2;
extern std::mutex sendlock1;

extern sendbuffer2 SENDBUFFER2;
extern sendbuffer1 SENDBUFFER1;

u_int16_t calculate_check_sum(ip_header* ip_hdr, int len)
{
	int sum = 0, tmp = len;
	u_int16_t* p = (u_int16_t*)ip_hdr;
	while (len > 1)
	{
		sum += *p;
		len -= 2;
		p++;
	}

	//len=1 last one byte
	if (len)
	{
		sum += *((u_int8_t*)ip_hdr + tmp - 1);
	}

	//fold 32 bits to 16 bits
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

void load_ip_header(u_int8_t* ip_buffer, u_int8_t upper_protocol_type)
{
	struct ip_header* ip_hdr = (struct ip_header*)ip_buffer;
	ip_size_of_packet = 0;
	//initial the ip header
	ip_hdr->version_hdrlen = 0x4f;//0200 2222 means ip version4 and header length: 60 bytes
	ip_hdr->type_of_service = 0xfe;/*222 2 2220: first 1 bits: priority level,
								   then 2 bit: delay, 2 bit: throughput, 2 bit: reliability
								   2 bit: routing cost, 2 bit: unused
								   */
	ip_hdr->total_length = 0;// wait for data length, 0 for now
	ip_hdr->id = ip_packet_id;//identification
	ip_hdr->fragment_offset = 0x0000;/*0 0 0 0 00...00: first 1 bits is flag: 2 bit: 0 the last fragment,
									 2 more fragmet. 2 bit: 0 allow fragment, 2 don't fragment. 2 bit: unused
									 the last 21 bits is offset
									 */
	ip_hdr->time_to_live = 64;//default 2000ms
	ip_hdr->upper_protocol_type = upper_protocol_type;//default upper protocol is tcp, IPPROTO_TCP
	ip_hdr->check_sum = 0;//initial zero

	int i;
	for (i = 0; i < 4; i++)
	{
		ip_hdr->source_ip[i] = local_ip[i];
		ip_hdr->destination_ip[i] = target_ip[i];
	}

	//initial check_sum is associate with offset. so in the data we need to calculate check_sum
	ip_size_of_packet += sizeof(ip_header);
}


int is_same_lan(u_int8_t* local_ip, u_int8_t* destination_ip)
{
	int i;
	for (i = 0; i < 4; i++)
	{
		if ((local_ip[i] & netmask[i]) != (destination_ip[i] & netmask[i]))
			return 0;
	}
	return 1;
}

DWORD WINAPI ip_send(LPVOID pM)
{
	while (1) {
		//若文件信息还未读完或者发送缓冲区还有数据未发出，需要继续发送
		sendlock2.lock();

		//get how many fragments
		int number_of_fragment = (int)ceil(SENDBUFFER2.size_of_packet[SENDBUFFER2.tail] * 1.0 / MAX_IP_PACKET_SIZE);
		u_int16_t offset = 0;
		int ip_data_len;
		u_int16_t fragment_offset;

		if (SENDBUFFER2.empty == false)
		{
			while (number_of_fragment != 0)
			{
				sendlock1.lock();

				if (SENDBUFFER1.full == false)
				{
					//load ip header to sendbuffer1
					load_ip_header(SENDBUFFER1.pool[SENDBUFFER1.head], SENDBUFFER2.proto_type[SENDBUFFER2.tail]);
					struct ip_header* ip_hdr = (struct ip_header*)SENDBUFFER1.pool[SENDBUFFER1.head];
					if (number_of_fragment == 1)//the last slice
					{
						fragment_offset = 0x0000;//26bits
						ip_data_len = SENDBUFFER2.size_of_packet[SENDBUFFER2.tail] - offset;
					}
					else
					{
						fragment_offset = 0x2000;//allow the next fragment
						ip_data_len = MAX_IP_PACKET_SIZE;
					}
					fragment_offset |= ((offset / 8) & 0x0fff);//get the fragment offset
					ip_hdr->fragment_offset = htons(fragment_offset);
					ip_hdr->total_length = htons(ip_data_len + sizeof(ip_header));
					ip_hdr->check_sum = calculate_check_sum(ip_hdr, 60);
					//for debug
					printf("[IP]   IP len = %d\n", ip_hdr->total_length);
					printf("[IP]   size of ipheader = %d\n", sizeof(ip_header));
					printf("\n[IP]	ip data len is %d\n", ip_data_len);

					//load ip data 
					for (int i = 0; i < ip_data_len; i++)
					{
						SENDBUFFER1.pool[SENDBUFFER1.head][i + sizeof(ip_header)] = SENDBUFFER2.pool[SENDBUFFER2.tail][i + offset];
						//printf("%c", SENDBUFFER1.pool[SENDBUFFER1.head][i + sizeof(ip_header)]);
					}
					offset += MAX_IP_PACKET_SIZE;
					printf("[IP]	ip_packet_id is %d,	number of fragment is %d\n", ip_packet_id, number_of_fragment);
					number_of_fragment--;

					//get the dest ip
					u_int8_t* dest_ip;
					//check if the target pc and the local host is in the same lan
					if (is_same_lan(local_ip, ip_hdr->destination_ip))
					{
						dest_ip = ip_hdr->destination_ip;
						printf("[ARP]	Dest IP:	");
						for (int i = 0; i < 4; i++)
						{
							if (i)printf(".");
							printf("%d", dest_ip[i]);
							dest_ip[i] = ip_hdr->destination_ip[i];
						}
						printf("\n");
					}
					else
					{
						dest_ip = gateway_ip;
					}

					u_int8_t* destination_mac = is_existed_ip(dest_ip);
					if (destination_mac == NULL)
					{
						arprecv_flag = true;//标志该进程将循环接收arp响应报文
						arp_req_send(dest_ip, broadcast_mac);//发送arp请求报文

						sendlock1.unlock();
					}

					if (arprecv_flag)
					{
						printf("[ARP]	ARP RESPONSE RECEIVE\n");
						destination_mac = arp_res_recv(dest_ip);//数据链路层获得响应报文
						arprecv_flag = false;

						sendlock1.lock();
					}

					SENDBUFFER1.ip_size_of_packet[SENDBUFFER1.head] = ip_data_len + sizeof(ip_header);
					SENDBUFFER1.type[SENDBUFFER1.head] = ETHERNET_IP;
					for (int j = 0; j < 6; j++)
					{
						SENDBUFFER1.destination_mac[SENDBUFFER1.head][j] = *(destination_mac + j);
					}
					SENDBUFFER1.head = (SENDBUFFER1.head + 1) % NUM_QUE;
					SENDBUFFER1.empty = false;
				}
				if (SENDBUFFER1.head == SENDBUFFER1.tail)
					SENDBUFFER1.full = true;
				sendlock1.unlock();
			}
			//auto increase one
			ip_packet_id++;

			SENDBUFFER2.tail = (SENDBUFFER2.tail + 1) % NUM_QUE;
			SENDBUFFER2.full = false;
		}

		if (SENDBUFFER2.head == SENDBUFFER2.tail)
			SENDBUFFER2.empty = true;
		sendlock2.unlock();
	}

	return 0;
}