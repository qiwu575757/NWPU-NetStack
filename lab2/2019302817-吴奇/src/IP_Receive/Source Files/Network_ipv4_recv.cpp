#include "Network_ipv4_recv.h"

ip_receivebuffer IP_RECEIVEBUFFER;
std::mutex mylock2;////定义互斥锁用于对 ip 缓冲区的互斥访问

char *accept_ip[2] = { {"255.255.255.255"}, {"192.168.0.1"} };
u_int16_t ip_id = 0;
u_int16_t total_len = 0;//记录整个ip数据报的长度
u_int8_t buffer[MAX_DATA_SIZE];

bool end_flag = false;
int previous = 0, current = 0;
int total_receive = 0;
/*
if allow fragment, store to buffer until not allow, then rebuild the ip data
	store to file.
*/

void init_ip_receivebuffer()
{
	IP_RECEIVEBUFFER.head = 0;
	IP_RECEIVEBUFFER.tail = 0;
	IP_RECEIVEBUFFER.full = false;
	IP_RECEIVEBUFFER.empty = true;
}

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

int is_accept_ip_packet(struct ip_header* ip_hdr)
{
	//this function translate the u_int32_t to char *
	char* destination_ip = inet_ntoa(ip_hdr->destination_ip);
	if (strcmp(destination_ip, accept_ip[0]) == 0)
	{
		printf("It's broadcast.\n");
	}
	else if (strcmp(destination_ip, accept_ip[1]) == 0)
	{
		printf("It's sended to my pc\n");
	}
	else
	{
		//printf("It's not acceptable ip\n");
		return 0;
	}

	u_int16_t check_sum = calculate_check_sum(ip_hdr, 60);
	if (check_sum == 0xffff || check_sum == 0x0000)
	{
		printf("No error in ip_header.\n");
	}
	else
	{
		printf("Error in ip_header\n");
		//network_icmpv4_recv(icmpv4_buffer);
		return 0;
	}
	if (ip_hdr->time_to_live == 0)
	{
		printf("TTL =0");
		//network_icmpv4_recv(icmpv4_buffer);
		return 0;
	}
}

void load_data_to_buffer(u_int8_t* buffer, u_int8_t* ip_data, int len)
{
	int i = 0;
	printf("load data to buffer start\n");
	for ( i = 0; i < len; i++ )
	{
		*(buffer + i) = *(ip_data + i);
	}
}

int load_data_to_file(u_int8_t* buffer, int len, FILE* fp)
{
	int res = fwrite(buffer, sizeof(u_int8_t), len, fp);
	if (res != len)
	{
		printf("Write file error!\n");
		return 0;
	}
	fflush(fp);
	return 1;
}

void swap_receivepool(int a, int b)
{
	u_int16_t temp;
	//swap fragment
	temp = DATALINK_IP_RECEIVEQUEUE.fragment[a];
	DATALINK_IP_RECEIVEQUEUE.fragment[a] = DATALINK_IP_RECEIVEQUEUE.fragment[b];
	DATALINK_IP_RECEIVEQUEUE.fragment[b] = temp;

	//swap pool
	int i;
	u_int8_t temp_data[1600];
	for (i = 0; i < 1600; i++)
	{
		temp_data[i] = DATALINK_IP_RECEIVEQUEUE.pool[a][i];
	}
	for (i = 0; i < 1600; i++)
	{
		DATALINK_IP_RECEIVEQUEUE.pool[a][i] = DATALINK_IP_RECEIVEQUEUE.pool[b][i];
	}
	for (i = 0; i < 1600; i++)
	{
		DATALINK_IP_RECEIVEQUEUE.pool[b][i] = temp_data[i];
	}
}

//由于收到的ip分组可能乱序，需要进行确认
int fragment_reassemble()//use to confirm the fragment is complete or not
{
	struct ip_header* ip_hdr;
	int tail = DATALINK_IP_RECEIVEQUEUE.tail;
	int head = DATALINK_IP_RECEIVEQUEUE.head;
	int i, j;
	u_int16_t fragment, m1, m2;
	//caculate the fragment of every slice
	while ( tail != head )
	{
		ip_hdr = (struct ip_header*)DATALINK_IP_RECEIVEQUEUE.pool[tail];
		fragment = ntohs(ip_hdr->fragment_offset) & 0x1fff;
		DATALINK_IP_RECEIVEQUEUE.fragment[tail] = fragment;
		tail = (tail + 1) % NUM_QUE;
	}

	//按照fragment 的顺序对接收的ip分组进行排序
	tail = DATALINK_IP_RECEIVEQUEUE.tail;
	head = DATALINK_IP_RECEIVEQUEUE.head;
	u_int16_t temp;
	for (i = tail; i != head; i = (i + 1) % NUM_QUE)
	{
		for (j = tail; j !=  i; j = (j + 1) % NUM_QUE)
		{
			if (DATALINK_IP_RECEIVEQUEUE.fragment[j] > DATALINK_IP_RECEIVEQUEUE.fragment[(j + 1) % NUM_QUE])
			{
				swap_receivepool(j, (j + 1) % NUM_QUE);
			}
		}
	}

	//对接收的ip 分组的是否丢失进行验证
	tail = DATALINK_IP_RECEIVEQUEUE.tail;
	head = DATALINK_IP_RECEIVEQUEUE.head;
	while (tail != head)
	{
		//可能有问题
		m1 = DATALINK_IP_RECEIVEQUEUE.fragment[((tail + 1) % NUM_QUE) * 8];
		m2 = DATALINK_IP_RECEIVEQUEUE.fragment[tail * 8];
		if (m1 != m2 + 1400)
		{
			return -1;
		}
	}

	return 0;
}

void update_thebuffer()
{
	//update the datalink_ip_receivequeue
	if (DATALINK_IP_RECEIVEQUEUE.full == false)
	{
		DATALINK_IP_RECEIVEQUEUE.tail = (DATALINK_IP_RECEIVEQUEUE.tail + 1) % NUM_QUE;
		DATALINK_IP_RECEIVEQUEUE.full = false;
	}
	if (DATALINK_IP_RECEIVEQUEUE.head == DATALINK_IP_RECEIVEQUEUE.tail)
		DATALINK_IP_RECEIVEQUEUE.empty = true;
}

DWORD WINAPI ipv4_receive(LPVOID pM)
{
	while (end_flag == false || DATALINK_IP_RECEIVEQUEUE.empty == false)
	{
		mylock1.lock();
		if (DATALINK_IP_RECEIVEQUEUE.empty == false)
		{
			//receive the newest ip slice 
			struct ip_header* ip_hdr = (struct ip_header*)DATALINK_IP_RECEIVEQUEUE.pool[DATALINK_IP_RECEIVEQUEUE.tail];

			//check the valid
			if ( !is_accept_ip_packet(ip_hdr) )
			{
				printf(" is not accept ip packet\n");
				update_thebuffer();
				mylock1.unlock();//用锁需注意啊，动不动就一个线程多次加锁就导致异常了
				continue;
			}

			int dural = 0;
			if (previous == 0)
			{
				previous = time(NULL);
			}
			else
			{
				//get current time
				current = time(NULL);
				dural = current - previous;
				printf("%d %d\n", current, previous);
				//current time became previous
				previous = current;
			}
			//interval can not larger than 30s，超时重传
			if (dural >= 30)
			{
				printf("Time Elapsed.\n");
				update_thebuffer();
				mylock1.unlock();//用锁需注意啊，动不动就一个线程多次锁定导致异常了
				continue;
			}

			u_int16_t fragment;
			fragment = ntohs(ip_hdr->fragment_offset);
			int len = ntohs(ip_hdr->total_length) - sizeof(ip_header);
			if ((fragment & 0x2000) && (ip_id == ip_hdr->id))//true means more fragment
			{
				printf("\n1.0 len = %d, totallen = %d\n", len, total_len+len);
				load_data_to_buffer(buffer + total_len, DATALINK_IP_RECEIVEQUEUE.pool[DATALINK_IP_RECEIVEQUEUE.tail] + sizeof(ip_header), len);
				total_len += len;
			}
			else //if (ip_id == ip_hdr->id)//no more fragment
			{
				//if ( fragment_reassemble() == -1 )
				//{
				//	printf("Lost packets................\n");
				//	//pass the last fragment make move
				//	total_len = 0;
				//	ip_id++;//每发送一个ip分组就加一，无论是否发送成功
				//}
				//use to copy the data from the buffer in ethernet to the buffer in ip network
				mylock2.lock();
				if (IP_RECEIVEBUFFER.full == false)
				{
					printf("\n2.0 len = %d, totallen = %d\n", len, total_len + len);
					load_data_to_buffer(buffer + total_len, DATALINK_IP_RECEIVEQUEUE.pool[DATALINK_IP_RECEIVEQUEUE.tail] + sizeof(ip_header), len);
					printf("\n3.0 len = %d, totallen = %d\n", len, total_len + len);
					total_len += len;
					load_data_to_buffer
							(IP_RECEIVEBUFFER.pool[IP_RECEIVEBUFFER.head], buffer, total_len);

					IP_RECEIVEBUFFER.total_len[IP_RECEIVEBUFFER.head] = total_len;
					IP_RECEIVEBUFFER.head = (IP_RECEIVEBUFFER.head + 1) % NUM_QUE;
					IP_RECEIVEBUFFER.empty = false;
					total_len = 0;
				}
				if (IP_RECEIVEBUFFER.head == IP_RECEIVEBUFFER.tail)
					IP_RECEIVEBUFFER.full = true;
				mylock2.unlock();

				if (total_receive == TOTAL_IP_GROUPS)//若到了第四个ip分组的最后，将结束标志置为 true
				{
					end_flag = true;
				}
				ip_id++;
			}
			//else
			//{
			//	printf("Lost packets.\n");
			//	//pass the last fragment make move
			//	total_len = 0;
			//	ip_id++;//每发送一个ip分组就加一，无论是否发送成功
			//	//printf("\nip id change, id = %d\n", ip_id);
			//}

			update_thebuffer();
		}
		mylock1.unlock();
	}

	return 0;
}

DWORD WINAPI ipv4_writetofile(LPVOID pM)
{
	init_ip_receivebuffer();
	FILE* fp = fopen("recv_data.txt", "w");
	while (end_flag == false || IP_RECEIVEBUFFER.empty == false)
	{
		mylock2.lock();
		if (IP_RECEIVEBUFFER.empty == false)
		{
			if (load_data_to_file(IP_RECEIVEBUFFER.pool[IP_RECEIVEBUFFER.tail],IP_RECEIVEBUFFER.total_len[IP_RECEIVEBUFFER.tail], fp))
			{
				printf("Load to file Succeed.\n");
			}
			IP_RECEIVEBUFFER.tail = (IP_RECEIVEBUFFER.tail + 1) % NUM_QUE;
			IP_RECEIVEBUFFER.full = false;
		}
		if (IP_RECEIVEBUFFER.head == IP_RECEIVEBUFFER.tail)
		{
			IP_RECEIVEBUFFER.empty = true;
		}
		mylock2.unlock();
	}
	fclose(fp);

	return 0;
}