#include "Network_ipv4_recv.h"

u_int16_t ip_id = 0;
u_int16_t total_len = 0;//记录整个ip数据报的长度
u_int8_t data_buffer[MAX_DATA_SIZE];//变量命名需注意啊

extern recvbuffer1 RECVBUFFER1;
extern recvbuffer2 RECVBUFFER2;
extern std::mutex recvlock1;//定义互斥锁用于对 ip 缓冲区的互斥访问
extern std::mutex recvlock2;//定义互斥锁用于对 ip 缓冲区的互斥访问

extern u_int8_t local_ip[4];
bool end_flag = false;
int previous = 0, current = 0;
int total_receive = 0;
/*
if allow fragment, store to data_buffer until not allow, then rebuild the ip data
	store to file.
*/

void init_recvbuffer2()
{
	RECVBUFFER2.head = 0;
	RECVBUFFER2.tail = 0;
	RECVBUFFER2.full = false;
	RECVBUFFER2.empty = true;
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
	int i;
	int flag = 0;
	for (i = 0; i < 4; i++)
	{
		if (ip_hdr->destination_ip[i] != local_ip[i])break;
	}

	if (i == 4)
	{
		flag = 1;
		printf("It's sended to my IP.\n");
	}

	for (i = 0; i < 4; i++)
	{
		if (ip_hdr->destination_ip[i] != 0xff)break;
	}
	if (i == 4)
	{
		flag = 1;
		printf("It's broadcast IP.\n");
	}

	if (!flag)
		return 0;

	u_int16_t check_sum = calculate_check_sum(ip_hdr, 60);
	if (check_sum == 0xffff || check_sum == 0x0000)
	{
		printf("No error in ip_header.\n");
	}
	else
	{
		printf("Error in ip_header\n");
		return 0;
	}

}

void load_data_to_buffer(u_int8_t* data_buffer, u_int8_t* ip_data, int len)
{
	int i = 0;
	printf("load data to buffer start\n");
	for (i = 0; i < len; i++)
	{
		*(data_buffer + i) = *(ip_data + i);
	}
}

int load_data_to_file(u_int8_t* data_buffer, int len, FILE* fp)
{
	int res = fwrite(data_buffer, sizeof(u_int8_t), len, fp);
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
	temp = RECVBUFFER1.fragment[a];
	RECVBUFFER1.fragment[a] = RECVBUFFER1.fragment[b];
	RECVBUFFER1.fragment[b] = temp;

	//swap pool
	int i;
	u_int8_t temp_data[1600];
	for (i = 0; i < 1600; i++)
	{
		temp_data[i] = RECVBUFFER1.pool[a][i];
	}
	for (i = 0; i < 1600; i++)
	{
		RECVBUFFER1.pool[a][i] = RECVBUFFER1.pool[b][i];
	}
	for (i = 0; i < 1600; i++)
	{
		RECVBUFFER1.pool[b][i] = temp_data[i];
	}
}

//由于收到的ip分组可能乱序，需要进行确认
int fragment_reassemble()//use to confirm the fragment is complete or not
{
	struct ip_header* ip_hdr;
	int tail = RECVBUFFER1.tail;
	int head = RECVBUFFER1.head;
	int i, j;
	u_int16_t fragment, m1, m2;
	//caculate the fragment of every slice
	while (tail != head)
	{
		ip_hdr = (struct ip_header*)RECVBUFFER1.pool[tail];
		fragment = ntohs(ip_hdr->fragment_offset) & 0x1fff;
		RECVBUFFER1.fragment[tail] = fragment;
		tail = (tail + 1) % NUM_QUE;
	}

	//按照fragment 的顺序对接收的ip分组进行排序
	tail = RECVBUFFER1.tail;
	head = RECVBUFFER1.head;
	u_int16_t temp;
	for (i = tail; i != head; i = (i + 1) % NUM_QUE)
	{
		for (j = tail; j != i; j = (j + 1) % NUM_QUE)
		{
			if (RECVBUFFER1.fragment[j] > RECVBUFFER1.fragment[(j + 1) % NUM_QUE])
			{
				swap_receivepool(j, (j + 1) % NUM_QUE);
			}
		}
	}

	//对接收的ip 分组的是否丢失进行验证
	tail = RECVBUFFER1.tail;
	head = RECVBUFFER1.head;
	while (tail != head)
	{
		//可能有问题
		m1 = RECVBUFFER1.fragment[((tail + 1) % NUM_QUE) * 8];
		m2 = RECVBUFFER1.fragment[tail * 8];
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
	if (RECVBUFFER1.full == false)
	{
		RECVBUFFER1.tail = (RECVBUFFER1.tail + 1) % NUM_QUE;
		RECVBUFFER1.full = false;
	}
	if (RECVBUFFER1.head == RECVBUFFER1.tail)
		RECVBUFFER1.empty = true;
}

DWORD WINAPI ipv4_receive(LPVOID pM)
{
	while (end_flag == false || RECVBUFFER1.empty == false)
	{
		recvlock1.lock();
		if (RECVBUFFER1.empty == false)
		{
			//receive the newest ip slice 
			struct ip_header* ip_hdr = (struct ip_header*)RECVBUFFER1.pool[RECVBUFFER1.tail];

			//check the valid
			if (!is_accept_ip_packet(ip_hdr))
			{
				printf(" is not accept ip packet\n");
				update_thebuffer();
				recvlock1.unlock();//用锁需注意啊，动不动就一个线程多次加锁就导致异常了
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
				recvlock1.unlock();//用锁需注意啊，动不动就一个线程多次锁定导致异常了
				continue;
			}

			u_int16_t fragment;
			fragment = ntohs(ip_hdr->fragment_offset);
			int len = ntohs(ip_hdr->total_length) - sizeof(ip_header);
			if ((fragment & 0x2000) && (ip_id == ip_hdr->id))//true means more fragment
			{
				printf("\n1.0 len = %d, totallen = %d\n", len, total_len + len);
				load_data_to_buffer(data_buffer + total_len, RECVBUFFER1.pool[RECVBUFFER1.tail] + sizeof(ip_header), len);
				total_len += len;
			}
			else 
			{
				recvlock2.lock();
				if (RECVBUFFER2.full == false)
				{
					printf("\n2.0 len = %d, totallen = %d\n", len, total_len + len);
					load_data_to_buffer(data_buffer + total_len, RECVBUFFER1.pool[RECVBUFFER1.tail] + sizeof(ip_header), len);
					printf("\n3.0 len = %d, totallen = %d\n", len, total_len + len);
					total_len += len;
					load_data_to_buffer(RECVBUFFER2.pool[RECVBUFFER2.head], data_buffer, total_len);

					RECVBUFFER2.total_len[RECVBUFFER2.head] = total_len;
					RECVBUFFER2.head = (RECVBUFFER2.head + 1) % NUM_QUE;
					RECVBUFFER2.empty = false;
					total_len = 0;
				}
				if (RECVBUFFER2.head == RECVBUFFER2.tail)
					RECVBUFFER2.full = true;
				recvlock2.unlock();

				if (total_receive == TOTAL_IP_GROUPS)//若到了第四个ip分组的最后，将结束标志置为 true
				{
					end_flag = true;
				}
				ip_id++;
			}
			update_thebuffer();
		}
		recvlock1.unlock();
	}

	return 0;
}

DWORD WINAPI ipv4_writetofile(LPVOID pM)
{
	init_recvbuffer2();
	FILE* fp = fopen("recv_data.txt", "w");
	while (end_flag == false || RECVBUFFER2.empty == false)
	{
		recvlock2.lock();
		if (RECVBUFFER2.empty == false)
		{
			if (load_data_to_file(RECVBUFFER2.pool[RECVBUFFER2.tail], RECVBUFFER2.total_len[RECVBUFFER2.tail], fp))
			{
				printf("Load to file Succeed.\n");
			}
			RECVBUFFER2.tail = (RECVBUFFER2.tail + 1) % NUM_QUE;
			RECVBUFFER2.full = false;
		}
		if (RECVBUFFER2.head == RECVBUFFER2.tail)
		{
			RECVBUFFER2.empty = true;
		}
		recvlock2.unlock();
	}
	fclose(fp);

	return 0;
}