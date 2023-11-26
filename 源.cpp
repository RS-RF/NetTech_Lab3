#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include <time.h>
BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    /*
    * 调用 GetSystemDirectory 函数获取系统目录路径，并将其存储在 npcap_dir 中。
    * 函数的第二个参数 480 表示 npcap_dir 变量的最大大小为 480。
    */
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    /*
    * 使用 _tcscat_s 函数将 \Npcap 字符串追加到 npcap_dir 变量末尾，形成完整的 Npcap 安装目录路径。
    */
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    /*
    * 调用 SetDllDirectory 函数设置 DLL 的搜索路径为 npcap_dir，使得程序可以找到并加载该目录下的 DLL 文件。如果函数返回值为 0，则说明设置失败，打印错误信息并返回 FALSE。
    */
    return TRUE;
}

#pragma pack(1)

//6字节的MAC地址
typedef struct MACAddress {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}MACAddress;

//4字节的IP地址
typedef struct IPAddress {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}IPAddress;

//FrameHeader
typedef struct FrameHeader {
    MACAddress destination_mac_address;
    MACAddress source_mac_address;
    WORD type;
}FrameHeader;

//ARPHeader
typedef struct ARPFrame {
    FrameHeader frame_header;
    WORD hardware_type;
    WORD protocol_type;
    BYTE h_len;
    BYTE p_len;
    WORD operation;
    BYTE send_ha[6];
    IPAddress send_ip;
    BYTE recv_ha[6];
    IPAddress recv_ip;
}APRFrame;

//IPHeader
typedef struct IPHeader {
    u_char  ver_ihl;//版本（4bits）和包头长度（4bits）
    u_char  tos;//服务类型
    u_short tlen;//总长度
    u_short identification;//标识
    u_short flags_fo;//标志和片偏移
    u_char  ttl;//生存周期
    u_char  proto;//协议
    u_short crc;//头部校验和
    IPAddress  saddr;//源IP地址
    IPAddress  daddr;//目的IP地址
    u_int  op_pad;//选择+填充
}IPHeader;
#pragma pack()

void setARP(ARPFrame* argu_arp, BYTE argu_send_ha[], IPAddress argu_send_ip, IPAddress argu_recv_ip) {
    // 设置目的地址为广播地址
    argu_arp->frame_header.destination_mac_address.byte1 = 0xFF;
    argu_arp->frame_header.destination_mac_address.byte2 = 0xFF;
    argu_arp->frame_header.destination_mac_address.byte3 = 0xFF;
    argu_arp->frame_header.destination_mac_address.byte4 = 0xFF;
    argu_arp->frame_header.destination_mac_address.byte5 = 0xFF;
    argu_arp->frame_header.destination_mac_address.byte6 = 0xFF;

    //设置本机网卡的MAC地址
    argu_arp->frame_header.source_mac_address.byte1 = argu_send_ha[0];
    argu_arp->frame_header.source_mac_address.byte2 = argu_send_ha[1];
    argu_arp->frame_header.source_mac_address.byte3 = argu_send_ha[2];
    argu_arp->frame_header.source_mac_address.byte4 = argu_send_ha[3];
    argu_arp->frame_header.source_mac_address.byte5 = argu_send_ha[4];
    argu_arp->frame_header.source_mac_address.byte6 = argu_send_ha[5];

    //设置帧类型为0x0806
    argu_arp->frame_header.type = htons(0x0806);

    //设置硬件类型为以太网
    argu_arp->hardware_type = htons(0x0001);

    //设置协议类型为IP
    argu_arp->protocol_type = htons(0x0800);

    //设置硬件地址长度为6
    argu_arp->h_len = 6;

    //设置协议地址长度为4
    argu_arp->p_len = 4;

    //设置操作为ARP请求
    argu_arp->operation = htons(0x0001);

    //设置本机网卡的MAC地址
    argu_arp->send_ha[0] = argu_send_ha[0];
    argu_arp->send_ha[1] = argu_send_ha[1];
    argu_arp->send_ha[2] = argu_send_ha[2];
    argu_arp->send_ha[3] = argu_send_ha[3];
    argu_arp->send_ha[4] = argu_send_ha[4];
    argu_arp->send_ha[5] = argu_send_ha[5];

    //设置本机网卡的IP地址
    argu_arp->send_ip.byte1 = argu_send_ip.byte1;
    argu_arp->send_ip.byte2 = argu_send_ip.byte2;
    argu_arp->send_ip.byte3 = argu_send_ip.byte3;
    argu_arp->send_ip.byte4 = argu_send_ip.byte4;

    //设置目的MAC地址为0
    argu_arp->recv_ha[0] = 0x00;
    argu_arp->recv_ha[1] = 0x00;
    argu_arp->recv_ha[2] = 0x00;
    argu_arp->recv_ha[3] = 0x00;
    argu_arp->recv_ha[4] = 0x00;
    argu_arp->recv_ha[5] = 0x00;

    //设置请求的IP地址
    argu_arp->recv_ip.byte1 = argu_recv_ip.byte1;
    argu_arp->recv_ip.byte2 = argu_recv_ip.byte2;
    argu_arp->recv_ip.byte3 = argu_recv_ip.byte3;
    argu_arp->recv_ip.byte4 = argu_recv_ip.byte4;
}

int main()
{
    pcap_if_t* alldevs;//用于存储所有的设备
    pcap_if_t* d;//用于遍历所有设备
    int dev_num;//要打开第几个设备
    int i = 0;//循环变量
    pcap_t* adhandle;//打开的网络接口设备
    char errbuf[PCAP_ERRBUF_SIZE];//存储错误信息的buffer
    u_int netmask;//子网掩码
    char packet_filter[] = "arp";//过滤器
    struct bpf_program fcode;

    pcap_addr_t* a;
    ARPFrame arp_frame;
    DWORD rev_ip;
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    ARPFrame* IPPacket;

    //加载NPcap相关函数，如果没有加载成功，那么输出错误信息并退出程序。
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Npcap加载错误\n");
        exit(1);
    }

    //获取网络设备列表，如果返回-1，说明函数执行失败，输出错误信息并退出程序。
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "pcap_findalldevs_ex执行失败: %s\n", errbuf);
        exit(1);
    }

    int count_dev = 0;

    printf("----------获取设备列表：----------\n");


    //输出设备列表，并用count_dev进行计数
    for (d = alldevs; d; d = d->next)
    {
        count_dev++;
        printf("%d. %s", count_dev, d->name);
        if (d->description)//对设备的描述
            printf(" (%s)\n", d->description);
        else
            printf(" (无描述)\n");

        //获取这一网络接口设备的IP地址信息
        for (a = d->addresses; a != NULL; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                // 输出IP地址
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(((struct sockaddr_in*)a->addr)->sin_addr), ip_str, INET_ADDRSTRLEN);
                printf("\tIP地址: %s\n", ip_str);

                // 输出子网掩码
                char netmask_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(((struct sockaddr_in*)a->netmask)->sin_addr), netmask_str, INET_ADDRSTRLEN);
                printf("\t子网掩码: %s\n", netmask_str);

                // 输出广播地址
                if (a->broadaddr) {
                    char broadaddr_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(((struct sockaddr_in*)a->broadaddr)->sin_addr), broadaddr_str, INET_ADDRSTRLEN);
                    printf("\t广播地址: %s\n", broadaddr_str);
                }

                // 输出目的地址
                if (a->dstaddr) {
                    char dstaddr_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(((struct sockaddr_in*)a->dstaddr)->sin_addr), dstaddr_str, INET_ADDRSTRLEN);
                    printf("\t目的地址: %s\n", dstaddr_str);
                }
            }
        }
    }
    printf("\n");

    //如果设备列表为空，则输出提示信息，主函数返回-1
    if (count_dev == 0)
    {
        printf("\n没有找到设备\n");
        return -1;
    }

    //输入设备的标号
    printf("----------选择设备：----------\n");
    printf("输入设备的标号:");
    scanf_s("%d", &dev_num);
    

    //检查dev_num的合法性
    if (dev_num < 1 || dev_num > count_dev)
    {
        printf("\n输入的标号超出范围！\n");
        pcap_freealldevs(alldevs);//释放所有的设备
        return -1;
    }

    //将d设置为选择的设备
    for (d = alldevs, i = 0; i < dev_num - 1; d = d->next, i++);

    //调用pcap_open,打开选定的网络接口设备，返回一个指向pcap_t类型的句柄adhandle
    if ((adhandle = pcap_open(
        d->name, //接口设备的名字
        65536, // 表示要捕获的数据包的最大大小，65536 表示捕获所有的数据
        PCAP_OPENFLAG_PROMISCUOUS, // 混杂模式
        1000, // 超时时间
        NULL, // 远程认证
        errbuf // error buffer
    )) == NULL)
    {
        fprintf(stderr, "\n打开选定的网络接口设备失败\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for (a = d->addresses; a != NULL; a = a->next) {
        if (a->addr->sa_family == AF_INET)
        {
            rev_ip = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
        }
    }

    //获取网络接口设备的子网掩码
    if (d->addresses != NULL)
    {
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else
    {
        //假设设备在一个C类网络中
        netmask = 0xffffff;
    }


    //编译网络数据包过滤器
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\n过滤器编译失败\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    //设置已编译的网络数据包过滤器。
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\n过滤器设置错误\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    IPAddress local_ip;
    local_ip.byte1 = rev_ip & 0xFF;
    local_ip.byte2 = (rev_ip>>8) & 0xFF;
    local_ip.byte3 = (rev_ip>>16) & 0xFF;
    local_ip.byte4 = (rev_ip>>24) & 0xFF;

    BYTE sh[6] = { 0x66,0x66,0x66,0x66,0x66,0x66 };
    IPAddress si;
    si.byte1 = 0x70;
    si.byte2 = 0x70;
    si.byte3 = 0x70;
    si.byte4 = 0x70;
    setARP(&arp_frame, sh, si, local_ip);
    pcap_sendpacket(adhandle, (u_char*)&arp_frame, sizeof(arp_frame));
    printf("ARP发送成功\n");

    while (true) {
        int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
        if (rtn == -1) {
            printf("在捕获ARP数据包时发生错误！\n");
            return 0;
        }
        else if(rtn == 0){
            printf("没有捕获到数据包！\n");
        }
        else {
            IPPacket = (ARPFrame*)pkt_data;
            if (IPPacket->recv_ip.byte1 == 0x70 
                && IPPacket->recv_ip.byte2 == 0x70
                && IPPacket->recv_ip.byte3 == 0x70
                && IPPacket->recv_ip.byte4 == 0x70
                && IPPacket->send_ip.byte1 == (rev_ip & 0xFF)
                && IPPacket->send_ip.byte2 == ((rev_ip >> 8) & 0xFF)
                && IPPacket->send_ip.byte3 == ((rev_ip >> 16) & 0xFF)
                && IPPacket->send_ip.byte4 == ((rev_ip >> 24) & 0xFF)
                )
            {
                printf("IP地址与MAC地址的对应关系如下：\n");
                printf("IP地址：%d.%d.%d.%d <==> MAC地址： %02x-%02x-%02x-%02x-%02x-%02x\n",
                    IPPacket->send_ip.byte1,
                    IPPacket->send_ip.byte2,
                    IPPacket->send_ip.byte3,
                    IPPacket->send_ip.byte4,

                    IPPacket->send_ha[0],
                    IPPacket->send_ha[1],
                    IPPacket->send_ha[2],
                    IPPacket->send_ha[3],
                    IPPacket->send_ha[4],
                    IPPacket->send_ha[5]
                );
                break;
            } 
        }
    }
    printf("\n");

    printf("----------输入IP地址：----------\n");
    printf("请输入IP地址：");
    char dest_ip[INET_ADDRSTRLEN];
    scanf("%s", dest_ip);
    DWORD dst_ip_dword = inet_addr(dest_ip);
    IPAddress dst_ip;
    dst_ip.byte1 = dst_ip_dword & 0xFF;
    dst_ip.byte2 = (dst_ip_dword >> 8) & 0xFF;
    dst_ip.byte3 = (dst_ip_dword >> 16) & 0xFF;
    dst_ip.byte4 = (dst_ip_dword >> 24) & 0xFF;
    BYTE dst_ha[6];
    for (int i = 0; i < 6; i++) {
        dst_ha[i] = IPPacket->send_ha[i];
    }
    setARP(&arp_frame,dst_ha, local_ip, dst_ip);
    pcap_sendpacket(adhandle, (u_char*)&arp_frame, sizeof(arp_frame));
    printf("ARP发送成功！\n");

    while (true) {
        int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
        if (rtn == -1) {
            printf("在捕获ARP数据包时发生错误！\n");
            return 0;
        }
        else if (rtn == 0) {
            printf("没有捕获到数据包！\n");
        }
        else {
            IPPacket = (ARPFrame*)pkt_data;
            if (IPPacket->recv_ip.byte1 == local_ip.byte1
                && IPPacket->recv_ip.byte2 == local_ip.byte2
                && IPPacket->recv_ip.byte3 == local_ip.byte3
                && IPPacket->recv_ip.byte4 == local_ip.byte4
                && IPPacket->send_ip.byte1 == dst_ip.byte1
                && IPPacket->send_ip.byte2 == dst_ip.byte2
                && IPPacket->send_ip.byte3 == dst_ip.byte3
                && IPPacket->send_ip.byte4 == dst_ip.byte4
                )//判断是不是一开始发的包
            {
                printf("IP地址与MAC地址的对应关系如下：\n");
                printf("IP地址：%d.%d.%d.%d <==> MAC地址： %02x-%02x-%02x-%02x-%02x-%02x\n",
                    IPPacket->send_ip.byte1,
                    IPPacket->send_ip.byte2,
                    IPPacket->send_ip.byte3,
                    IPPacket->send_ip.byte4,

                    IPPacket->send_ha[0],
                    IPPacket->send_ha[1],
                    IPPacket->send_ha[2],
                    IPPacket->send_ha[3],
                    IPPacket->send_ha[4],
                    IPPacket->send_ha[5]
                );
                break;
            }
        }
    }

    pcap_freealldevs(alldevs);

    return 0;
}
