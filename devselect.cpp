#include "devselect.h"
#include "ui_devselect.h"
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <QDebug>
#include "dialog.h"
//extern QString devName;
DevSelect::DevSelect(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::devselect)
{
    ui->setupUi(this);

    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    /* 获取当前计算机的所有网络设备 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qDebug()<<"1!";

        ui->devList->insertItem(0,"");
        qDebug()<<"未找到设备，请确认此程序在root权限下运行!";
    }
    /* 打印列表 */
    for(d=alldevs; d; d=d->next) {
        qDebug()<<QString(d->name);
        ui->devList->insertItem(i++,d->name);
    }
    pcap_freealldevs(alldevs);
    ipFlag=arpFlag=icmpFlag=tcpFlag=udpFlag = false;



}

DevSelect::~DevSelect()
{
    delete ui;
}



void DevSelect::on_ipButton_clicked()
{
    if(ui->ipButton->checkState() == 0)
        ipFlag = false;
    else
        ipFlag = true;
}

void DevSelect::on_ARPButton_clicked()
{
    if(ui->ARPButton->checkState() == 0)
        arpFlag = false;
    else
        arpFlag = true;
}

void DevSelect::on_icmpButton_clicked()
{
    if(ui->icmpButton->checkState() == 0)
        icmpFlag = false;
    else
        icmpFlag = true;
}

void DevSelect::on_tcpBox_clicked()
{
    if(ui->tcpBox->checkState() == 0)
        tcpFlag = false;
    else
        tcpFlag = true;
}

void DevSelect::on_udpBox_clicked()
{
    if(ui->udpBox->checkState() == 0)
        udpFlag = false;
    else
        udpFlag = true;
}


void DevSelect::on_buttonBox_accepted()
{
    QString boolExp;
    if(ipFlag || arpFlag || icmpFlag) {
        QString tmp;
        //tmp += "(";
        if(ipFlag)
            tmp += "ip ";
        if(arpFlag)
            tmp += "arp ";
        if(icmpFlag)
            tmp += "icmp ";
        //tmp += ") ";
        boolExp += tmp;
    }
    if(ui->tcpBox->checkState() || ui->udpBox->checkState()) {
        QString tmp;
        tmp += "and (";
        if(ui->tcpBox->checkState() )
            tmp += "tcp ";
        if(ui->udpBox->checkState())
            tmp += "udp ";
        tmp += ") ";
        boolExp += tmp;
    }
    if(!ui->sipLineEdit->text().isEmpty() || !ui->dipLineEdit->text().isEmpty()) {
        QString tmp;
        tmp += "and (src host ";
        tmp += ui->sipLineEdit->text();
        tmp += " and dst host ";
        tmp += ui->dipLineEdit->text();
        tmp += ") ";
        boolExp += tmp;
    }
    if(!ui->portEdit->text().isEmpty()) {
        QString tmp;
        tmp += "and (port ";
        tmp += ui->portEdit->text();
        tmp += ") ";
        boolExp += tmp;
    }
    if(!ui->smacLineEdit->text().isEmpty() || !ui->dmacLineEdit->text().isEmpty()) {
        QString tmp;
        tmp += "and (ether src ";
        tmp += ui->smacLineEdit->text();
        tmp += " and ether dst ";
        tmp += ui->dmacLineEdit->text();
        tmp += ") ";
        boolExp += tmp;
    }
    qDebug() << boolExp;
//////////////////////////////////////////
    qDebug()<<"0";
    Dialog mainWin(0,ui->devList->currentItem()->text() , boolExp);
    qDebug()<<"1";
    mainWin.exec();
    qDebug()<<"2";
    close();


}

void DevSelect::on_buttonBox_rejected()
{
    close();
}
