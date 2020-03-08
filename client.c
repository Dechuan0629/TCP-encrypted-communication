#include <stdio.h>
#include<time.h>
#include<math.h>
#include <stdlib.h>
#pragma comment(lib,"ws2_32.lib")
#include <Winsock2.h>
#include <Ws2tcpip.h>
#define SIO_RCVALL            _WSAIOW(IOC_VENDOR,1)
#include <time.h>
#include <string.h>
#define HELLO_WORLD_SERVER_PORT       5555
#define BUFFER_SIZE                   1024
#define FILE_NAME_MAX_SIZE            512
#define bzero(a, b)             memset(a, 0, b)
#include <sys/stat.h>
#include <openssl/des.h>
#include <openssl/pkcs7.h>
#ifndef uchar
#define uchar unsigned char
#endif

int main(int argc, char* argv[])
    {
        WORD sockVersion = MAKEWORD(2,2);
        WSADATA data;
        if(WSAStartup(sockVersion, &data) != 0)
        {
            return 0;
        }
        SOCKET sclient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(sclient == INVALID_SOCKET)
        {
            printf("CLIENT:invalid socket!");
            return 0;
        }
        SOCKADDR_IN serAddr;
        serAddr.sin_family = AF_INET;
        serAddr.sin_port = htons(5555);

        struct hostent *pHostent;
        char Name[255];
        int Result;
        Result = gethostname(Name, 255);
        if (Result == SOCKET_ERROR)
        {
            printf("CLIENT:gethostname failed with error %d\n", WSAGetLastError());
            return 0;
        }
        pHostent = (struct hostent*)malloc(sizeof(struct hostent));
        pHostent = gethostbyname(Name);
        memcpy(&serAddr.sin_addr.S_un.S_addr, pHostent->h_addr_list[0], pHostent->h_length);

        if (connect(sclient, (SOCKADDR *)&serAddr, sizeof(serAddr)) == SOCKET_ERROR)
        {
            printf("CLIENT:connect error !");
            closesocket(sclient);
            return 0;
        }


        char * sendData = "Hello,this is client!!\n";
        send(sclient, sendData, strlen(sendData), 0);
        char recData[255];
        int ret = recv(sclient, recData, 255, 0);
        if(ret > 0)
        {
            recData[ret] = 0x00;
            printf("SERVER:%s\n",recData);
        }

        char buffer_G[5] = {0};                 //----------------------DH密钥协商过程
        char buffer_P[5] = {0};
        int msg1 = recv(sclient,buffer_G,5,0);
        if(msg1>0)
        {
            buffer_G[msg1] = 0x00;
            printf("SERVER:G is %s\n",buffer_G);
        }

        int msg2 = recv(sclient,buffer_P,3,0);
        if(msg2>0)
        {
            buffer_P[msg2] = 0x00;
            printf("SERVER:P is %s\n",buffer_P);
        }

        int G = atoi(buffer_G);
        int P = atoi(buffer_P);
        bzero(buffer_G, sizeof(buffer_G));
        bzero(buffer_P, sizeof(buffer_P));
        int G_P[2] = {0};
        G_P[0] = G;
        G_P[1] = P;
        srand(time(NULL));
		int B = rand()%(90)+32;
		printf("\nB - %d\n",B);
		int SB = RandomSB(G_P,B);
		printf("SB is %d\n",SB);
		char buffer_SB[10] = {0};
		itoa(SB,buffer_SB,10);
		send(sclient,buffer_SB,strlen(buffer_SB),0);
        bzero(buffer_SB, sizeof(buffer_SB));
		char buffer_SA[10] = {0};
		int msg3 = recv(sclient,buffer_SA,10,0);
		if(msg3>0)
        {
            buffer_SA[msg1] = 0x00;
            printf("SERVER:SA is %s\n",buffer_SA);
        }
        int SA = atoi(buffer_SA);
        bzero(buffer_SA, sizeof(buffer_SA));
        int Key2=MoChongFua(SA,B,G_P[0]);
        printf("key = %d\n",Key2);             //----------------------DH密钥协商过程
        char Key[10] = {0};
        itoa(Key2,Key,10);

        char file_name[FILE_NAME_MAX_SIZE + 1];
        bzero(file_name, sizeof(file_name));
        printf("Please Input File Name On Server.\t");
        scanf("%s", file_name);

        char buffer[BUFFER_SIZE];
        bzero(buffer, sizeof(buffer));
        strncpy(buffer, file_name, strlen(file_name) > BUFFER_SIZE ? BUFFER_SIZE : strlen(file_name));
        // 向服务器发送buffer中的数据，此时buffer中存放的是客户端需要接收的文件的名字
        send(sclient, buffer, BUFFER_SIZE, 0);

        FILE *fp = fopen(file_name, "wb");
        if (fp == NULL)
        {
            printf("File:\t%s Can Not Open To Write!\n", file_name);
            exit(1);
        }

        // 从服务器端接收数据到buffer中
        bzero(buffer, sizeof(buffer));
        int length = 0;
        while(length = recv(sclient, buffer, BUFFER_SIZE, 0))
        {
            Buffer_DES_Decrypt(buffer,BUFFER_SIZE,Key);//解密函数-对缓冲区内的数据进行加解密
            if (length < 0)
            {
                printf("Recieve Data From Server %s Failed!\n", argv[1]);
                break;
            }
            int write_length = fwrite(buffer, sizeof(char), length, fp);
            if (write_length < length)
            {
                printf("File:\t%s Write Failed!\n", file_name);
                break;
            }
            bzero(buffer, BUFFER_SIZE);

        }

        printf("Recieve File:\t %s From Server[%s] Finished!\n", file_name, argv[1]);

        // 传输完毕，关闭socket
        fclose(fp);

        closesocket(sclient);
        WSACleanup();
        return 0;
    }

void Buffer_DES_Decrypt(char buffer[],int size1,char key_dh[])
{
    unsigned char keystring[10];
    strcpy(keystring,key_dh);

    DES_cblock key;
    DES_key_schedule key_schedule;

    //生成一个 key
    DES_string_to_key(keystring, &key);
    if (DES_set_key_checked(&key, &key_schedule) != 0) {
      printf("convert to key_schedule failed.\n");
      return -1;
    }

    //需要加密的字符串
    unsigned char input[BUFFER_SIZE];
    bzero(input, sizeof(input));
    memcpy(input,buffer,size1);
    size_t len = (size1+7)/8 * 8;
    unsigned char output[BUFFER_SIZE+1];
    //IV
    bzero(output, sizeof(output));
    DES_cblock ivec;

    //IV设置为0x0000000000000000
    memset((char*)&ivec, 0, sizeof(ivec));

    //解密
    DES_ncbc_encrypt(input, output, len, &key_schedule, &ivec, DES_DECRYPT);
    memcpy(buffer,output,size1);

    return EXIT_SUCCESS;
}

int RandomSB(int G_P[],int B)
{
    int SB = 0;
    SB = MoChongFua(G_P[1],B,G_P[0]);
    return SB;
}

int MoChongFu(int m, int e,int n)
{
	int binary[22];
	int count=0,i;
	int a=1,b;
    b=m;
	do{
		binary[count]=e%2;
		e=e/2;
		count++;
	}while(e!=0);

	for(i=0;i<count;i++)
	{
		if(binary[i]==1)
		{
			a=(a*b)%n;
			b=(b*b)%n;
		}
		if(binary[i]==0)
		{
			a=a;
			b=(b*b)%n;
		}

	}
	return a;
}
int MoChongFua(int m, int e,int n)
{
	int binary[22];
	int count=0,i;
	int a=1,b;
    b=m;

	do{
		binary[count]=e%2;
		e=e/2;
		count++;
	}while(e!=0);

	for(i=0;i<count;i++)
	{
		if(binary[i]==1)
		{
			a=(a*b)%n;
			b=(b*b)%n;
		}
		if(binary[i]==0)
		{
			a=a;
			b=(b*b)%n;
		}

	}
	return a;
}
