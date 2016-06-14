#include "pcapThread.h"
#include <qdebug.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
PcapThread::PcapThread(QString devName)
{
    char*  devNameCh;
    QByteArray ba = devName.toLatin1();
    devNameCh=ba.data();
    char *net_interface;
    net_interface = devNameCh;//QString转化为Char*
    struct ifaddrs * ifAddrStruct=NULL;
    void * tmpAddrPtr=NULL;
    if(getifaddrs(&ifAddrStruct))
        localIP = QString("获取失败");
    while (ifAddrStruct!=NULL) {
        if ((ifAddrStruct->ifa_addr->sa_family==AF_INET )&& (QString(ifAddrStruct->ifa_name)==devName)) {
            tmpAddrPtr = &((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            localIP = QString(addressBuffer);
            break;
        }
        if(ifAddrStruct!=NULL) ifAddrStruct = ifAddrStruct->ifa_next;
    }

    /* Libpcap句柄 */
    char error_content[PCAP_ERRBUF_SIZE];
    /* 错误信息 */
    //char *net_interface;
    /* 网络接口 */
    struct bpf_program bpf_filter;
    /* bpf过滤规则 */
    char bpf_filter_string[] = "ip";
    /* 过滤规则字符串，此时表示本程序只是捕获IP协议的网络数据包 */
    bpf_u_int32 net_mask;
    /* 网络掩码 */
    bpf_u_int32 net_ip;
    /* 网络地址 */
    //net_interface = pcap_lookupdev(error_content);
    /* 获得网络接口 */
    pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);
    /* 获得网路地址和掩码 */
    pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 0, error_content);
    /* 打开网络接口 */
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    /* 编译BPF过滤规则 */
    pcap_setfilter(pcap_handle, &bpf_filter);
    /* 设置过滤规则 */
    packet_number = 0;
}

PcapThread::~PcapThread()
{
    pcap_close(pcap_handle);

}

void PcapThread::run()
{
    qDebug()<<"thread init!";

    while((res = pcap_next_ex(pcap_handle,&pcap_pkthdr,&packet_content)) >= 0)
        /* 注册回调函数，循环捕获数据包 */
    {
        qDebug()<<"thread is running";
        if(res == 0)
            continue;
        ethernetProtocolPacketCallback(packet_content);
    }

}

void PcapThread::ipProtocolPacketCallback(const u_char *packet_content)
{
    struct ip_header *ip_protocol;
    ip_protocol = (struct ip_header*)(packet_content + 14);
    struct ipValue tmpVlue;
    tmpVlue.sIP = QString(inet_ntoa(ip_protocol->ip_souce_address));
    tmpVlue.dIP = QString(inet_ntoa(ip_protocol->ip_destination_address));

    if(tmpVlue.sIP == localIP||tmpVlue.dIP== localIP) {
        switch (ip_protocol->ip_protocol) { /* 判断协议类型的值 */
        case 6:
            tmpVlue.kind = QString("TCP");
            break;
        /* 如果协议类型为6，表示上层协议为TCP协议 */
        case 17:
            tmpVlue.kind = QString("UDP");
            break;
        /* 如果协议类型为17，表示上层协议为UDP协议 */
        case 1:
            tmpVlue.kind = QString("ICMP");
            break;
        /* 如果协议类型为1，表示传上层协议为ICMP协议 */
        default:
            break;
        }
        tmpVlue.count = 1;
        QString tmpKey = tmpVlue.sIP + tmpVlue.dIP + tmpVlue.kind;
        QMap<QString, struct ipValue>::iterator itr = map.find(tmpKey);
        if(itr == map.end()) {
            map[tmpKey] = tmpVlue;
        } else {
            map[tmpKey].count++;
        }
        qDebug()<<"ip msg get";
    }


}


void PcapThread::ethernetProtocolPacketCallback(const u_char *packet_content)
{
    u_short ethernet_type;
    /* 以太网类型 */
    struct ether_header *ethernet_protocol;
    ethernet_protocol = (struct ether_header*)packet_content;
    //    /* 获得以太网协议数据内容 */
    ethernet_type = ntohs(ethernet_protocol->ether_type);
    switch (ethernet_type) {
    case 0x0800:
        ipProtocolPacketCallback(packet_content);
        break;
    /*
     * 如果上层协议是IP协议，就调用分析IP协议的函数对IP协议进行分析。
     */
    default:
        break;
    }
    packet_number++;
}

