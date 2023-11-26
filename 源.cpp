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
    * ���� GetSystemDirectory ������ȡϵͳĿ¼·����������洢�� npcap_dir �С�
    * �����ĵڶ������� 480 ��ʾ npcap_dir ����������СΪ 480��
    */
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    /*
    * ʹ�� _tcscat_s ������ \Npcap �ַ���׷�ӵ� npcap_dir ����ĩβ���γ������� Npcap ��װĿ¼·����
    */
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    /*
    * ���� SetDllDirectory �������� DLL ������·��Ϊ npcap_dir��ʹ�ó�������ҵ������ظ�Ŀ¼�µ� DLL �ļ��������������ֵΪ 0����˵������ʧ�ܣ���ӡ������Ϣ������ FALSE��
    */
    return TRUE;
}

#pragma pack(1)

//6�ֽڵ�MAC��ַ
typedef struct MACAddress {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}MACAddress;

//4�ֽڵ�IP��ַ
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
    u_char  ver_ihl;//�汾��4bits���Ͱ�ͷ���ȣ�4bits��
    u_char  tos;//��������
    u_short tlen;//�ܳ���
    u_short identification;//��ʶ
    u_short flags_fo;//��־��Ƭƫ��
    u_char  ttl;//��������
    u_char  proto;//Э��
    u_short crc;//ͷ��У���
    IPAddress  saddr;//ԴIP��ַ
    IPAddress  daddr;//Ŀ��IP��ַ
    u_int  op_pad;//ѡ��+���
}IPHeader;
#pragma pack()

void setARP(ARPFrame* argu_arp, BYTE argu_send_ha[], IPAddress argu_send_ip, IPAddress argu_recv_ip) {
    // ����Ŀ�ĵ�ַΪ�㲥��ַ
    argu_arp->frame_header.destination_mac_address.byte1 = 0xFF;
    argu_arp->frame_header.destination_mac_address.byte2 = 0xFF;
    argu_arp->frame_header.destination_mac_address.byte3 = 0xFF;
    argu_arp->frame_header.destination_mac_address.byte4 = 0xFF;
    argu_arp->frame_header.destination_mac_address.byte5 = 0xFF;
    argu_arp->frame_header.destination_mac_address.byte6 = 0xFF;

    //���ñ���������MAC��ַ
    argu_arp->frame_header.source_mac_address.byte1 = argu_send_ha[0];
    argu_arp->frame_header.source_mac_address.byte2 = argu_send_ha[1];
    argu_arp->frame_header.source_mac_address.byte3 = argu_send_ha[2];
    argu_arp->frame_header.source_mac_address.byte4 = argu_send_ha[3];
    argu_arp->frame_header.source_mac_address.byte5 = argu_send_ha[4];
    argu_arp->frame_header.source_mac_address.byte6 = argu_send_ha[5];

    //����֡����Ϊ0x0806
    argu_arp->frame_header.type = htons(0x0806);

    //����Ӳ������Ϊ��̫��
    argu_arp->hardware_type = htons(0x0001);

    //����Э������ΪIP
    argu_arp->protocol_type = htons(0x0800);

    //����Ӳ����ַ����Ϊ6
    argu_arp->h_len = 6;

    //����Э���ַ����Ϊ4
    argu_arp->p_len = 4;

    //���ò���ΪARP����
    argu_arp->operation = htons(0x0001);

    //���ñ���������MAC��ַ
    argu_arp->send_ha[0] = argu_send_ha[0];
    argu_arp->send_ha[1] = argu_send_ha[1];
    argu_arp->send_ha[2] = argu_send_ha[2];
    argu_arp->send_ha[3] = argu_send_ha[3];
    argu_arp->send_ha[4] = argu_send_ha[4];
    argu_arp->send_ha[5] = argu_send_ha[5];

    //���ñ���������IP��ַ
    argu_arp->send_ip.byte1 = argu_send_ip.byte1;
    argu_arp->send_ip.byte2 = argu_send_ip.byte2;
    argu_arp->send_ip.byte3 = argu_send_ip.byte3;
    argu_arp->send_ip.byte4 = argu_send_ip.byte4;

    //����Ŀ��MAC��ַΪ0
    argu_arp->recv_ha[0] = 0x00;
    argu_arp->recv_ha[1] = 0x00;
    argu_arp->recv_ha[2] = 0x00;
    argu_arp->recv_ha[3] = 0x00;
    argu_arp->recv_ha[4] = 0x00;
    argu_arp->recv_ha[5] = 0x00;

    //���������IP��ַ
    argu_arp->recv_ip.byte1 = argu_recv_ip.byte1;
    argu_arp->recv_ip.byte2 = argu_recv_ip.byte2;
    argu_arp->recv_ip.byte3 = argu_recv_ip.byte3;
    argu_arp->recv_ip.byte4 = argu_recv_ip.byte4;
}

int main()
{
    pcap_if_t* alldevs;//���ڴ洢���е��豸
    pcap_if_t* d;//���ڱ��������豸
    int dev_num;//Ҫ�򿪵ڼ����豸
    int i = 0;//ѭ������
    pcap_t* adhandle;//�򿪵�����ӿ��豸
    char errbuf[PCAP_ERRBUF_SIZE];//�洢������Ϣ��buffer
    u_int netmask;//��������
    char packet_filter[] = "arp";//������
    struct bpf_program fcode;

    pcap_addr_t* a;
    ARPFrame arp_frame;
    DWORD rev_ip;
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    ARPFrame* IPPacket;

    //����NPcap��غ��������û�м��سɹ�����ô���������Ϣ���˳�����
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Npcap���ش���\n");
        exit(1);
    }

    //��ȡ�����豸�б��������-1��˵������ִ��ʧ�ܣ����������Ϣ���˳�����
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "pcap_findalldevs_exִ��ʧ��: %s\n", errbuf);
        exit(1);
    }

    int count_dev = 0;

    printf("----------��ȡ�豸�б�----------\n");


    //����豸�б�����count_dev���м���
    for (d = alldevs; d; d = d->next)
    {
        count_dev++;
        printf("%d. %s", count_dev, d->name);
        if (d->description)//���豸������
            printf(" (%s)\n", d->description);
        else
            printf(" (������)\n");

        //��ȡ��һ����ӿ��豸��IP��ַ��Ϣ
        for (a = d->addresses; a != NULL; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                // ���IP��ַ
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(((struct sockaddr_in*)a->addr)->sin_addr), ip_str, INET_ADDRSTRLEN);
                printf("\tIP��ַ: %s\n", ip_str);

                // �����������
                char netmask_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(((struct sockaddr_in*)a->netmask)->sin_addr), netmask_str, INET_ADDRSTRLEN);
                printf("\t��������: %s\n", netmask_str);

                // ����㲥��ַ
                if (a->broadaddr) {
                    char broadaddr_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(((struct sockaddr_in*)a->broadaddr)->sin_addr), broadaddr_str, INET_ADDRSTRLEN);
                    printf("\t�㲥��ַ: %s\n", broadaddr_str);
                }

                // ���Ŀ�ĵ�ַ
                if (a->dstaddr) {
                    char dstaddr_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(((struct sockaddr_in*)a->dstaddr)->sin_addr), dstaddr_str, INET_ADDRSTRLEN);
                    printf("\tĿ�ĵ�ַ: %s\n", dstaddr_str);
                }
            }
        }
    }
    printf("\n");

    //����豸�б�Ϊ�գ��������ʾ��Ϣ������������-1
    if (count_dev == 0)
    {
        printf("\nû���ҵ��豸\n");
        return -1;
    }

    //�����豸�ı��
    printf("----------ѡ���豸��----------\n");
    printf("�����豸�ı��:");
    scanf_s("%d", &dev_num);
    

    //���dev_num�ĺϷ���
    if (dev_num < 1 || dev_num > count_dev)
    {
        printf("\n����ı�ų�����Χ��\n");
        pcap_freealldevs(alldevs);//�ͷ����е��豸
        return -1;
    }

    //��d����Ϊѡ����豸
    for (d = alldevs, i = 0; i < dev_num - 1; d = d->next, i++);

    //����pcap_open,��ѡ��������ӿ��豸������һ��ָ��pcap_t���͵ľ��adhandle
    if ((adhandle = pcap_open(
        d->name, //�ӿ��豸������
        65536, // ��ʾҪ��������ݰ�������С��65536 ��ʾ�������е�����
        PCAP_OPENFLAG_PROMISCUOUS, // ����ģʽ
        1000, // ��ʱʱ��
        NULL, // Զ����֤
        errbuf // error buffer
    )) == NULL)
    {
        fprintf(stderr, "\n��ѡ��������ӿ��豸ʧ��\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for (a = d->addresses; a != NULL; a = a->next) {
        if (a->addr->sa_family == AF_INET)
        {
            rev_ip = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
        }
    }

    //��ȡ����ӿ��豸����������
    if (d->addresses != NULL)
    {
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else
    {
        //�����豸��һ��C��������
        netmask = 0xffffff;
    }


    //�����������ݰ�������
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\n����������ʧ��\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    //�����ѱ�����������ݰ���������
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\n���������ô���\n");
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
    printf("ARP���ͳɹ�\n");

    while (true) {
        int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
        if (rtn == -1) {
            printf("�ڲ���ARP���ݰ�ʱ��������\n");
            return 0;
        }
        else if(rtn == 0){
            printf("û�в������ݰ���\n");
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
                printf("IP��ַ��MAC��ַ�Ķ�Ӧ��ϵ���£�\n");
                printf("IP��ַ��%d.%d.%d.%d <==> MAC��ַ�� %02x-%02x-%02x-%02x-%02x-%02x\n",
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

    printf("----------����IP��ַ��----------\n");
    printf("������IP��ַ��");
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
    printf("ARP���ͳɹ���\n");

    while (true) {
        int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
        if (rtn == -1) {
            printf("�ڲ���ARP���ݰ�ʱ��������\n");
            return 0;
        }
        else if (rtn == 0) {
            printf("û�в������ݰ���\n");
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
                )//�ж��ǲ���һ��ʼ���İ�
            {
                printf("IP��ַ��MAC��ַ�Ķ�Ӧ��ϵ���£�\n");
                printf("IP��ַ��%d.%d.%d.%d <==> MAC��ַ�� %02x-%02x-%02x-%02x-%02x-%02x\n",
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
