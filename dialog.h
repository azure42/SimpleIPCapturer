#ifndef DIALOG_H
#define DIALOG_H
#include <QDialog>
#include <QMap>
#include "pcapThread.h"

namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
//    explicit Dialog(QWidget *parent = 0);
    explicit Dialog(QWidget *parent = 0,QString name=NULL ,QString fpCode = NULL);
    ~Dialog();

private slots:
    void msgUpdate();
    void on_startButton_clicked();

private:
    Ui::Dialog *ui;
    PcapThread *pcapThread;
    QString devName;
    QTimer *timer;
};

#endif // DIALOG_H
