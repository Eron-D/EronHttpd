//����Eron_C++��Ŀ_0.1��EronHttpd
//windowsϵͳ������httpd����������
//������127.0.0.1:2002 
//�˿ڣ�2002
//�ļ���ֲ������Ҫ���ļ��У�\htdocs
//��ҳ�ļ���htdocs\index.html

//Ŀǰ���״���Ľ׶ΰ汾���ո���ɣ�����ͨ���ܹ���ʾ��ҳ
// �Ž�github
//��һ���׶ΰ汾��ÿһ��ÿһ�д��붼�����Լ���ע��

#define _CRT_SECURE_NO_WARNINGS//�����ϻ������ʹ��ͨ����Ʊ
//c++��׼��
#include <stdio.h>
#include <string.h>
//c++ϵͳ���
#include <sys/types.h>
#include <sys/stat.h>
// ���������ͷ�ļ�
#include <WinSock2.h>
#include <process.h>  // �������̴�����ص�ͷ�ļ�������ʹ�� _beginthreadex ����
#pragma comment(lib, "WS2_32.lib")  // ���� Windows �����

// ��ӡ�궨��
#define PRINTF(str) printf("[%s - %d]"#str"=%s\n", __func__, __LINE__, str);  // �Զ����ӡ�꣬��ӡ���������кź��ַ���
// ������������ӡ������Ϣ���˳�����
void error_die(const char* str) {
    perror(str);  // ��ӡϵͳ������Ϣ
    exit(1);  // �����쳣��ֹ
}

// ʵ������ĳ�ʼ��
int startup(unsigned short* port) {
    WSADATA data;  // �洢 Winsock ��ʼ����Ϣ
    // ��ʼ�� Winsock �⣬ʹ�� 2.2 �汾
    int ret = WSAStartup(MAKEWORD(2, 2), &data);
    if (ret != 0) {  // ����ʼ���Ƿ�ɹ�
        error_die("WSAStartup");  // ��ʼ��ʧ������ô�������
    }

    // ���� TCP ��ʽ�׽���
    int server_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {  // ����׽��ִ����Ƿ�ɹ�
        error_die("�׽���");  // �׽��ִ���ʧ������ô�������
    }

    int opt = 1;  // �����׽���ѡ�ʹ��ַ�ɸ���
    // �����׽���ѡ�� SO_REUSEADDR
    ret = setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (ret == SOCKET_ERROR) {  // ����׽���ѡ�������Ƿ�ɹ�
        error_die("setsockopt");  // �׽���ѡ������ʧ������ô�������
    }

    // ���÷������˵������ַ�ṹ
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));  // ��յ�ַ�ṹ
    server_addr.sin_family = AF_INET;  // ���õ�ַ��Ϊ IPv4
    server_addr.sin_port = htons(*port);  // ���˿ں�ת��Ϊ�����ֽ���
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // �� IP ��ַ����Ϊ�����ַ

    // ���׽��ְ󶨵���������ַ
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        error_die("bind");  // ��ʧ������ô�������
    }

    int nameLen = sizeof(server_addr);  // ��ȡ��ַ�ṹ����
    // ���˿�Ϊ 0����̬��ȡ����Ķ˿ں�
    if (*port == 0) {
        if (getsockname(server_socket, (struct sockaddr*)&server_addr, &nameLen) == SOCKET_ERROR) {
            error_die("getsockname");  // ��ȡ�˿ں�ʧ������ô�������
        }
        *port = server_addr.sin_port;  // ���¶˿ں�
    }

    // ��ʼ�����ͻ������ӣ��������г���Ϊ 5
    if (listen(server_socket, 5) == SOCKET_ERROR) {
        error_die("listen");  // ����ʧ������ô�������
    }

    return server_socket;  // ���ط������׽���
}

// ��ָ���Ŀͻ����׽��ֶ�ȡһ�����ݣ����浽 buff ��
int get_line(int sock, char* buff, int size) {
    char c = 0;  // �洢��ȡ���ַ�
    int i = 0;  // �洢�Ѷ�ȡ�ַ�������
    // ѭ����ȡ�ַ���ֱ���������з��򻺳�������
    while (i < size - 1 && c != '\n') {
        // ���׽��ֶ�ȡһ���ַ�
        int n = recv(sock, &c, 1, 0);
        if (n > 0) {  // �ɹ���ȡ�ַ�
            if (c == '\r') {  // ����ǻس���
                // �鿴��һ���ַ��Ƿ�Ϊ���з�
                recv(sock, &c, 1, MSG_PEEK);
                if (c == '\n') {  // ���ǣ����ȡ�û��з�
                    recv(sock, &c, 1, 0);
                }
                else {  // �����ǣ��򽫵�ǰ�ַ���Ϊ���з�
                    c = '\n';
                }
            }
            buff[i++] = c;  // ���ַ��洢��������
        }
        else {  // δ�ɹ���ȡ�ַ�
            c = '\n';  // ��Ϊ�������з�
        }
    }
    buff[i] = 0;  // �ַ�����β��� '\0'
    return i;  // ����ʵ�ʶ�ȡ���ֽ���
}

// ��ָ�����׽��ַ���һ����ʾ��û��ʵ�ֵĴ���ҳ��
void unimplement(int client) {
    // ���� HTTP 501 δʵ�ֵ���Ӧ��Ϣ
    const char* message = "HTTP/1.1 501 Not Implemented\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 21\r\n"
        "\r\n"
        "501 Not Implemented";
    // ���ʹ�����Ϣ
    send(client, message, strlen(message), 0);
}

// ��ͻ��˷��� 404 δ�ҵ��Ĵ�����Ӧ
void not_found(int client) {
    char buff[1024];  // �洢��Ӧ��Ϣ
    // ���������� HTTP 404 ��Ӧ��Ϣ
    snprintf(buff, sizeof(buff), "HTTP/1.1 404 Not Found\r\n"
        "Server: EronHttpd/1.0\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>404 Not Found</H1></BODY></HTML>");
    // ���� 404 ��Ӧ��Ϣ
    send(client, buff, strlen(buff), 0);
}

// ��ͻ��˷��� HTTP 200 OK ��Ӧͷ
void headers(int client, const char* type) {
    char buff[1024];  // �洢��Ӧͷ��Ϣ
    // �������״̬�� 200 ���������͵���Ӧͷ
    snprintf(buff, sizeof(buff), "HTTP/1.1 200 OK\r\n"
        "Server: EronHttpd/1.0\r\n"
        "Content-Type: %s\r\n"
        "\r\n", type);
    // ������Ӧͷ
    send(client, buff, strlen(buff), 0);
}

// ���ļ���ȡ���ݲ����͸��ͻ���
void cat(int client, FILE* resource) {
    char buff[4096];  // �洢�ļ����ݵĻ�����
    int count = 0;  // ��¼�ѷ��͵��ֽ���
    // ѭ����ȡ�ļ����ݲ�����
    while (1) {
        // ���ļ���ȡ����
        int ret = fread(buff, sizeof(char), sizeof(buff), resource);
        if (ret <= 0) {  // ��ȡ���������
            break;
        }
        // ���Ͷ�ȡ������
        send(client, buff, ret, 0);
        count += ret;  // �����ѷ����ֽ���
    }
    // ��ӡ�ѷ��͵��ֽ���
    printf("һ������[%d]�ֽڸ������\n", count);
}

// �����ļ�����׺ȷ����������
const char* getHeadType(const char* fileName) {
    const char* ret = "text/html";  // Ĭ����������
    const char* p = strrchr(fileName, '.');  // �����ļ���׺
    if (!p) return ret;  // δ�ҵ���׺�򷵻�Ĭ������
    p++;  // �ƶ�ָ�뵽��׺��ʼλ��
    // ���ݺ�׺ȷ����������
    if (!strcmp(p, "css")) ret = "text/css";
    else if (!strcmp(p, "jpg")) ret = "image/jpeg";
    else if (!strcmp(p, "png")) ret = "image/png";
    else if (!strcmp(p, "js")) ret = "application/x-javascript";
    return ret;  // ������������
}

// ����ͻ���������ļ�����
void server_file(int client, const char* fileName) {
    int numchars = 1;  // �洢��ȡ�е��ַ���
    char buff[1024];  // �洢��ȡ��������
    // ��ȡ�������ݰ���ʣ��������
    while (numchars > 0 && strcmp(buff, "\n")) {
        numchars = get_line(client, buff, sizeof(buff));  // ���ж�ȡ
        PRINTF(buff);  // ��ӡ��ȡ����
    }

    FILE* resource = NULL;  // �洢�ļ�ָ��
    // ���ļ������� index.html ���ı�ģʽ�򿪣������ļ��Զ�����ģʽ��
    if (strcmp(fileName, "htdocs/index.html") == 0) {
        resource = fopen(fileName, "rb");
    }
    else {
        resource = fopen(fileName, "rb");
    }
    if (resource == NULL) {  // �ļ�������
        not_found(client);  // ���� 404 ������Ӧ
    }
    else {
        // �����ļ���Ӧͷ
        headers(client, getHeadType(fileName));
        // �����ļ�����
        cat(client, resource);
        printf("��Դ������ϣ�\n");  // ��ӡ���������Ϣ
        fclose(resource);  // �ر��ļ�
    }
}

// �����û�������̺߳���
DWORD WINAPI accept_request(LPVOID arg) {
    char buff[1024];  // �洢���յ���������
    // ��ȡ�ͻ����׽���
    int client = (SOCKET)arg;
    // �ӿͻ����׽��ֶ�ȡһ����������
    int numchars = get_line(client, buff, sizeof(buff));
    PRINTF(buff);  // ��ӡ��ȡ����������

    char method[255];  // �洢���󷽷�
    int j = 0, i = 0;  // ��������
    // �������󷽷�
    while (!isspace(buff[j]) && i < sizeof(method) - 1) {
        method[i++] = buff[j++];
    }
    method[i] = 0;  // �ַ�����β��� '\0'
    PRINTF(method);  // ��ӡ���󷽷�

    // ������󷽷��Ƿ�Ϊ GET �� POST
    if (_stricmp(method, "GET") && _stricmp(method, "POST")) {
        unimplement(client);  // ��֧�ֵ����󷽷������� 501 ������Ӧ
        return 0;
    }

    char url[255];  // �洢����� URL
    i = 0;
    // �����������еĿո�
    while (isspace(buff[j]) && j < sizeof(buff)) {
        j++;
    }
    // ��������� URL
    while (!isspace(buff[j]) && i < sizeof(url) - 1 && j < sizeof(buff)) {
        url[i++] = buff[j++];
    }
    url[i] = 0;  // �ַ�����β��� '\0'
    PRINTF(url);  // ��ӡ����� URL

    char path[512] = "htdocs";  // �洢������Դ���ļ�·��
    // ƴ���ļ�·��
    strncat(path, url, sizeof(path) - strlen(path) - 1);
    if (path[strlen(path) - 1] == '/') {  // �����Ŀ¼������� index.html
        strncat(path, "index.html", sizeof(path) - strlen(path) - 1);
    }
    PRINTF(path);  // ��ӡ�ļ�·��

    struct stat status;  // �洢�ļ�״̬��Ϣ
    // ��ȡ�ļ�״̬
    if (stat(path, &status) == -1) {
        // ��ȡ�������ݰ���ʣ��������
        while (numchars > 0 && strcmp(buff, "\n")) {
            numchars = get_line(client, buff, sizeof(buff));
            PRINTF(buff);
        }
        not_found(client);  // �ļ������ڣ����� 404 ������Ӧ
    }
    else {
        if ((status.st_mode & S_IFMT) == S_IFDIR) {  // �����Ŀ¼
            strncat(path, "/index.html", sizeof(path) - strlen(path) - 1);  // ��� index.html
        }
        // �����ļ�����
        server_file(client, path);
    }
    // �رտͻ����׽���
    closesocket(client);
    return 0;
}

int main(void) {
    unsigned short port = 2002;  // �����������Ķ˿ں�
    // ��������������ȡ�������׽���
    int server_sock = startup(&port);
    // ��ӡ������������Ϣ
    printf("httpd �����Ѿ����������ڼ��� %d �˿�.........\n", port);

    struct sockaddr_in client_addr;  // �洢�ͻ��˵�ַ
    int client_addr_len = sizeof(client_addr);  // �ͻ��˵�ַ����

    // ѭ���ȴ��ͻ�������
    while (1) {
        // ���ܿͻ�������
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_sock == INVALID_SOCKET) {  // ����ʧ��
            error_die("accept");  // ���ô�������
        }

        unsigned int threadId;  // �洢�̱߳�ʶ��
        // �����̴߳���ͻ�������
        _beginthreadex(NULL, 0, (unsigned int(__stdcall*)(void*))accept_request, (void*)client_sock, 0, &threadId);
    }
    // �رշ������׽���
    closesocket(server_sock);
    return 0;
}