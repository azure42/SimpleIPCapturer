#ifndef DEVSELECT_H
#define DEVSELECT_H

#include <QDialog>

namespace Ui {
class devselect;
}

class DevSelect : public QDialog
{
    Q_OBJECT

public:
    explicit DevSelect(QWidget *parent = 0);
//    explicit DevSelect(QString devName);
    ~DevSelect();

private slots:
    void on_closeButton_clicked();

    void on_okButton_clicked();

private:
    Ui::devselect *ui;
};

#endif // DEVSELECT_H
