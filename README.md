# 基于libPcap和Qt的ip流量分析工具
 - PcapThread类，继承自QThread，即Qt框架中跨平台多线程库。主要负责读取ip流量数据。其中定义一哈希表QMap<QString,struct ipValue>，QString为源地址、目的地至、协议内容相连接得到的唯一标识符，结构体ipValue则负责储存具体的数据。该线程中，每当pcap捕获到包时，pcap_next函数返回值正常，调用ipProtocolPacketCallback函数解析包中的流量数据，按需存储到哈希表当中。
 - DevSelect类，继承自QDialog，主要负责遍历设备列表并进行选择，选择结果通过字符串形式由构造函数发送给Dialog类mainWin。
 
  ![image](https://github.com/azure42/ipCapturer/raw/master/1.png )
 - Dialog类，继承自QDialog，即Qt中基础UI库。主要负责图形界面的绘制和刷新。在其构造函数中建立一PcapThread类，并由按键触发控制命令来控制其是否运行。定时从PcapThread类的实现中读取public型的哈希表，在表格中填充数据。
 
  ![image](https://github.com/azure42/ipCapturer/raw/master/2.png )

