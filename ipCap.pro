#-------------------------------------------------
#
# Project created by QtCreator 2016-06-11T20:21:42
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = ipCap
TEMPLATE = app

LIBS += -lpcap

SOURCES += main.cpp\
        dialog.cpp \
    pcapThread.cpp \
    devselect.cpp

HEADERS  += dialog.h \
    pcapThread.h \
    devselect.h

FORMS    += dialog.ui \
    devselect.ui
