#ifndef THREADDLG_H
#define THREADDLG_H

#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>
#include <QMap>
#include <arpa/inet.h>
#include <QThread>

struct ipValue
{
    QString sIP;
    QString dIP;
    QString kind;
    int count;
};

class PcapThread : public QThread
{
public:
    PcapThread(QString devName);
    ~PcapThread();
    int packet_number;
    QMap<QString,struct ipValue> map;
    QString localIP;
private:
    void ethernetProtocolPacketCallback(const u_char *packet_content);
    void ipProtocolPacketCallback(const u_char *packet_content);
    pcap_t *pcap_handle;
    int res;
    struct pcap_pkthdr *pcap_pkthdr;
    const u_char *packet_content;

protected:
    void run();
signals:
    void done(void);

};

struct ether_header
{
    u_int8_t ether_dhost[6];
    /* 目的以太网地址 */
    u_int8_t ether_shost[6];
    /* 源以太网地址 */
    u_int16_t ether_type;
    /* 以太网类型 */
};

struct ip_header
{
#ifdef WORDS_BIGENDIAN
    u_int8_t ip_version: 4,  /* IP协议版本 */
        ip_header_length: 4; /* IP协议首部长度 */
#else
    u_int8_t ip_header_length: 4, ip_version: 4;
#endif
    u_int8_t ip_tos;
    /* TOS服务质量 */
    u_int16_t ip_length;
    /* 总长度 */
    u_int16_t ip_id;
    /* 标识 */
    u_int16_t ip_off;
    /* 偏移 */
    u_int8_t ip_ttl;
    /* 生存时间 */
    u_int8_t ip_protocol;
    /* 协议类型 */
    u_int16_t ip_checksum;
    /* 校验和 */
    struct in_addr ip_souce_address;
    /* 源IP地址 */
    struct in_addr ip_destination_address;
    /* 目的IP地址 */
};

#endif // THREADDLG_H
