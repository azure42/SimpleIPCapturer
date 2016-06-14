#include "dialog.h"
#include "devselect.h"
#include <QApplication>
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    DevSelect devSelect;
    devSelect.show();
    return a.exec();
}
