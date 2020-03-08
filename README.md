# 信息安全综合实践：基于原始套接字的网络安全编程

## 实践内容
完成基于winsock的网络编程，实现计算机之间进行文件传输，在此基础上，对传输的数据流进行加密，到达接收方后，接收方能够正确解密。同时进行加密传输之前进行密钥协商。

## 实践环境
* 操作系统：`Windows10`
* 编程语言：`C`
* 加密算法：`DES`

## 实践步骤
1. Winsock头文件
2. Winsock库的装入、初始化和释放
3. 套节字的创建和关闭
4. 绑定套接字
5. 设置套接字
6. 利用原始套接字构造数据包并发送
7. 利用原始套接字接收数据包
