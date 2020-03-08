#include <stdio.h>
#include <stdlib.h>
#include<time.h>
#include<math.h>
#include <sys/stat.h>
#pragma comment(lib,"ws2_32.lib")
#include <Winsock2.h>
#include <Ws2tcpip.h>
#define SIO_RCVALL            _WSAIOW(IOC_VENDOR,1)
#include <time.h>
#define LENGTH_OF_LISTEN_QUEUE     20
#define BUFFER_SIZE                1024
#define FILE_NAME_MAX_SIZE         512
#define bzero(a, b)             memset(a, 0, b)
#pragma comment(lib,"libeay32.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#include <sys/stat.h>
#include <openssl/des.h>
#include <openssl/pkcs7.h>
#ifndef uchar
#define uchar unsigned char
#endif

int main()
{
    int Result;
    WSADATA wsaData;
    SOCKET *ps;

    Result = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (Result == SOCKET_ERROR)
    {
        printf("SERVER:WSAStartup failed with error %d\n", Result);
        return 0;
    }
    printf("SERVER:Version: %d.%d\n",LOBYTE(wsaData.wVersion),HIBYTE(wsaData.wVersion));
    printf("SERVER:High Version: %d.%d\n", LOBYTE(wsaData.wHighVersion),HIBYTE(wsaData.wHighVersion) );
    printf("SERVER:Description: %s\n",wsaData.szDescription );
    printf("SERVER:System Status: %s\n",wsaData.szSystemStatus );

    socket_create(ps);
    socket_server(ps);

    if(WSACleanup()==SOCKET_ERROR)
        printf("SERVER:WSACleanup³ö´í\n");

    return 0;
}

void socket_create(SOCKET *s)
{
    int Result;
    printf("\n-------Creating socket-------\n");
    *s = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (*s ==INVALID_SOCKET)
    {
        printf("SERVER:socket failed with error %d\n", WSAGetLastError());
        closesocket(*s);
        return 0;
    }
    else
        printf("SERVER:socket succeed!\n");

    char Name[255];
    Result = gethostname(Name, 255);
    if (Result == SOCKET_ERROR)
    {
        printf("SERVER:gethostname failed with error %d\n", WSAGetLastError());
        return 0;
    }
    struct hostent *pHostent;
    pHostent = (struct hostent*)malloc(sizeof(struct hostent));
    pHostent = gethostbyname(Name);
    SOCKADDR_IN sock;
    sock.sin_family = AF_INET;
    sock.sin_port = htons(5555);
    memcpy(&sock.sin_addr.S_un.S_addr, pHostent->h_addr_list[0], pHostent->h_length);

    Result = bind(*s, (PSOCKADDR) &sock, sizeof(sock));
    if (Result == SOCKET_ERROR)
    {
        printf("SERVER:bind failed with error %d\n", WSAGetLastError());
        closesocket(*s);
        return 0;
    }
    else
        printf("SERVER:bind succeed!\n");
        printf("-----------------------------\n\n");

}

void socket_server(SOCKET *s)
{
    time_t seconds;
    seconds = time(NULL);
    if(listen(*s, 5) == SOCKET_ERROR)
    {
        printf("SERVER:listen error !");
        return 0;
    }

    SOCKET sClient;
    SOCKADDR_IN remoteAddr;
    int nAddrlen = sizeof(remoteAddr);
    char revData[255];

    while (1)
    {
        printf("SERVER:Waiting for connection...\n");
        sClient = accept(*s, (SOCKADDR *)&remoteAddr, &nAddrlen);
        if(sClient == INVALID_SOCKET)
        {
            printf("SERVER:accept error !");
            continue;
        }
        printf("SERVER:Receving a connection:%s\r\n", inet_ntoa(remoteAddr.sin_addr));

        int G_P[2];//得到大素数G，P
        int G,P;
        DH_Key(G_P);
        G = G_P[0];
        P = G_P[1];

        int ret = recv(sClient, revData, 255, 0);
        if(ret > 0)
        {
            revData[ret] = 0x00;
            printf("CLIENT:%s\n",revData);
        }
        char * sendData = "Hello,Client!\n";
        send(sClient, sendData, strlen(sendData), 0);

        char buffer_G[10] = {0};              //----------------------DH密钥协商过程
        char buffer_P[10] = {0};
        itoa(G,buffer_G,10);
        itoa(P,buffer_P,10);
        printf("\nG,P = %s,%s\n",buffer_G,buffer_P);

        send(sClient,buffer_G,strlen(buffer_G),0);
        bzero(buffer_G, sizeof(buffer_G));
        send(sClient,buffer_P,strlen(buffer_P),0);
        bzero(buffer_P, sizeof(buffer_P));
        srand(time(NULL));
		int A = rand()%(96)+32;
		printf("\nA - %d\n",A);
		int SA = RandomSA(G_P,A);
		printf("SA is %d\n",SA);
		char buffer_SA[10] = {0};
		itoa(SA,buffer_SA,10);
		send(sClient,buffer_SA,strlen(buffer_SA),0);
        bzero(buffer_SA, sizeof(buffer_SA));
		char buffer_SB[10] = {0};
		int msg1 = recv(sClient,buffer_SB,10,0);
		if(msg1>0)
        {
            buffer_SB[msg1] = 0x00;
            printf("CLIENT:SB is %s\n",buffer_SB);
        }
        int SB = atoi(buffer_SB);
        bzero(buffer_SB, sizeof(buffer_SB));
        int Key1=MoChongFua(SB,A,G_P[0]);
        printf("key = %d\n",Key1);                 //-------------DH密钥协商过程
        char Key[10] = {0};
        itoa(Key1,Key,10);

        char buffer[BUFFER_SIZE];
        bzero(buffer, sizeof(buffer));
        int length = recv(sClient, buffer, BUFFER_SIZE, 0);
        if (length < 0)
        {
            printf("Server Recieve Data Failed!\n");
            break;
        }

        char file_name[FILE_NAME_MAX_SIZE + 1];
        bzero(file_name, sizeof(file_name));
        strncpy(file_name, buffer,
                strlen(buffer) > FILE_NAME_MAX_SIZE ? FILE_NAME_MAX_SIZE : strlen(buffer));
        char path_name[300]="D:\\CodeBlocksLAB\\C\\test\\bin\\Debug\\";
        strcat(path_name,file_name);
        FILE *fp = fopen(path_name, "rb");
        if (fp == NULL)
        {
            printf("File:\t%s Not Found!\n", file_name);
        }
        else
        {
            bzero(buffer, BUFFER_SIZE);
            int file_block_length = 0;
            while( (file_block_length = fread(buffer, sizeof(char), BUFFER_SIZE, fp)) > 0)
            {
                // 发送buffer中的字符串到new_server_socket,实际上就是发送给客户端
                Buffer_DES_Encrypt(buffer,BUFFER_SIZE,Key); //加密函数-对缓冲区内的数据进行加解密
                if (send(sClient, buffer, file_block_length, 0) < 0)
                {
                    printf("Send File:\t%s Failed!\n", file_name);
                    break;
                }
                printf("block_length:%d\n",file_block_length);
                bzero(buffer, sizeof(buffer));
            }

            fclose(fp);
            printf("File:\t%s Transfer Finished!\n", file_name);
        }
        shutdown(sClient,SD_SEND);
        closesocket(sClient);
    }
    closesocket(*s);
}

int file_size(char *filename)
{
    struct stat statbuf;
    int ret;
    ret = stat(filename,&statbuf);
    if(ret!=0)
        return 0;
    return statbuf.st_size;
}


void Buffer_DES_Encrypt(char buffer[],int size1,char key_dh[])
{

    unsigned char keystring[10] = {0};
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
    unsigned char input[BUFFER_SIZE+1];
    bzero(input, sizeof(input));
    memcpy(input,buffer,size1);
    size_t len = (size1+7)/8 * 8;
    unsigned char output[BUFFER_SIZE+1];
    bzero(output, sizeof(output));
    //IV
    DES_cblock ivec;

    //IV设置为0x0000000000000000
    memset((char*)&ivec, 0, sizeof(ivec));

    //加密
    DES_ncbc_encrypt(input, output, len, &key_schedule, &ivec, DES_ENCRYPT);

    memset((char*)&ivec, 0, sizeof(ivec));

    //解密
    //DES_ncbc_encrypt(output, input, len, &key_schedule, &ivec, 0);

    memcpy(buffer,output,size1);

    return EXIT_SUCCESS;
}

//DH密钥交换---------------------------
int Random_Odd();
int SPrime(int odd);
int MoChongFu(int m, int e,int n);
int MoChongFua(int m, int e,int n);
int milejiance(int odd);
int yuangen(int yy);
int S_PrimeTable[7] = { 3, 5, 7, 11, 13, 17, 19 };


void DH_Key(int G_P[])
{
	int yy=0;
	int gg;
	int A,B,Key,Key1,Key2;
	int SA,SB;

	int  i,flag1,flag2;
	do
	{
		q:while(yy == Random_Odd());
		yy = Random_Odd();
		flag1=!SPrime(yy);
		for(i=0;i<5;i++)
		{
			flag2=!milejiance(yy);
			if(flag2)
			{
				goto q;
			}
		}
	}

	while(flag1||flag2);
	gg=yuangen(yy);
	G_P[0] = yy;
	G_P[1] = gg;
}

int RandomSA(int G_P[],int A)
{
    int SA = 0;
    SA = MoChongFua(G_P[1],A,G_P[0]);
    return SA;
}

//产生一个随机数
int Random_Odd()
{
	int odd = 0;
	while (1)
	{
		srand(time(NULL));
		odd = rand() % (16384) + 16384;
		if (odd % 2 != 0)
			break;
	}
	//printf("%d\n", odd);
	return odd;
}


//如果是素数的话返回1
int SPrime(int odd)
{
	int i, r, k = 0;

 	for (i = 0; i<7; i++)
	{
		r = odd % S_PrimeTable[i];
		if (r == 0)
		{
		    return 0;
		}
	}
	return 1;
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

//米勒检测

int milejiance(int odd)
{
	int s=0,i,count=0;
	int a,b,t,num;
	num=odd-1;
	while(1)
	{
		if(num%2==0)
		{
			s++;
			num=num/2;
		}
		else
		{
			t=num;
			break;
		}
	}
	a=rand()%(odd-3)+2;
	b=MoChongFu(a,t,odd);

	if(b%odd==1||b==(odd-1))
	{

		return 1;
	}
	for(i=1;i<s;i++)
	{

		b=(b*b)%odd;
		if(b==(odd-1))
		{
			return 1;
		}

	}

	return 0;
}



//欧拉函数的素因数和两者的商
int yuangen(int yy)
{
	int n=2,g=0,q,k,j=0,a[10];
	int gg;
	int c[10];

	q=yy-1;

	while(1)
	{
    	if (q%n==0)
		{
			a[j]=n;
			j++;
			while(!(q%n))
			{
				q=q/n;
			}
		}
		n++;
		if(q<n)
			break;
	}

	for(n=0;n<j;++n)
	{

	}

	for(n=0;n<j;++n)
	{
		c[n]=(yy-1)/a[n];
	}
	for(g=2;;g++)
	{
		for(n=0;n<j;++n)
		{
			if(MoChongFu(g,c[n],yy)==1)
			{
				goto cd;
			}
		}
		gg=g;
		goto ab;
cd: ;
	}
ab:	for(g=3;;g++)
	{
		if((yy-1)%g!=0)
		{
			k=MoChongFu(gg,g,yy);
			if(k>32&&k<1024)
			{
				return k;
			}
		}
	}
	return 0;
}

