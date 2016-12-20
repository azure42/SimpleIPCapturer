#include "dialog.h"
#include "ui_dialog.h"
#include <QTimer>
#include <QDebug>
Dialog::Dialog(QWidget *parent , QString name , QString fpCode) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    qDebug()<<"mainWindow";
    ui->setupUi(this);
    devName = name;
    pcapThread = new PcapThread(devName , fpCode);
    QTimer *timer = new QTimer;
    connect(timer,SIGNAL(timeout()),
            this,SLOT(msgUpdate()));
    pcapThread->start();//抓包线程启动
    timer->start(1000);//界面每秒刷新
    qDebug()<<" Please ensure that this program runs in root authority!";
}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::msgUpdate()
{
    int row=0;
    QMap<QString, struct ipValue>::iterator itr = pcapThread->map.begin();
    while(itr != pcapThread->map.end()) {
        QTableWidgetItem *newItem0 = new QTableWidgetItem(itr.value().sIP);
        ui->msgTable->setItem(row,0,newItem0);
        QTableWidgetItem *newItem1 = new QTableWidgetItem(itr.value().dIP);
        ui->msgTable->setItem(row,1,newItem1);
        QTableWidgetItem *newItem2 = new QTableWidgetItem(itr.value().kind);
        ui->msgTable->setItem(row,2,newItem2);
        QTableWidgetItem *newItem3 = new QTableWidgetItem(QString::number(itr.value().count));
        ui->msgTable->setItem(row,3,newItem3);
        itr++;
        row++;
    }
    ui->ipLabel->setText("监听设备："+devName+"    设备IP："+pcapThread->localIP+"    捕获包总量："+QString::number(pcapThread->packet_number));
    ui->textBrowser->setText(pcapThread->outputStr);
    qDebug()<<"UI update";

}


void Dialog::on_startButton_clicked()
{
    static bool flag=0;
    flag = !flag;
    if(flag) {
        ui->startButton->setText("开始抓包");
        pcapThread->terminate();
        //timer->stop();
    } else {
        ui->startButton->setText("暂停抓包");
        pcapThread->start();
        //timer->start();
    }

}
