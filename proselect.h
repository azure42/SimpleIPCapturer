#ifndef PROSELECT_H
#define PROSELECT_H

#include <QDialog>

namespace Ui {
class proSelect;
}

class proSelect : public QDialog
{
    Q_OBJECT

public:
    explicit proSelect(QWidget *parent = 0);
    ~proSelect();

private slots:
    void on_ipButton_clicked();

    void on_ARPButton_clicked();

    void on_icmpButton_clicked();

    void on_tcpBox_clicked();

    void on_udpBox_clicked();

    void on_buttonBox_rejected();

    void on_buttonBox_accepted();

private:
    Ui::proSelect *ui;
    bool ipFlag,arpFlag,icmpFlag,tcpFlag,udpFlag;
};

#endif // PROSELECT_H
