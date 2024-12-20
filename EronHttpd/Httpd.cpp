//泷柠Eron_C++项目_0.1：EronHttpd
//windows系统轻量级httpd服务器代码
//域名：127.0.0.1:2002 
//端口：2002
//文件移植中最重要的文件夹：\htdocs
//网页文件：htdocs\index.html

//目前这套代码的阶段版本：刚刚完成，调试通过能够显示网页
// 放进github
//下一步阶段版本：每一条每一行代码都打上自己的注释

#define _CRT_SECURE_NO_WARNINGS//几种老化代码的使用通关门票
//c++标准库
#include <stdio.h>
#include <string.h>
//c++系统编程
#include <sys/types.h>
#include <sys/stat.h>
// 服务器相关头文件
#include <WinSock2.h>
#include <process.h>  // 包含进程处理相关的头文件，用于使用 _beginthreadex 函数
#pragma comment(lib, "WS2_32.lib")  // 链接 Windows 网络库

// 打印宏定义
#define PRINTF(str) printf("[%s - %d]"#str"=%s\n", __func__, __LINE__, str);  // 自定义打印宏，打印函数名、行号和字符串
// 错误处理函数，打印错误信息并退出程序
void error_die(const char* str) {
    perror(str);  // 打印系统错误信息
    exit(1);  // 程序异常终止
}

// 实现网络的初始化
int startup(unsigned short* port) {
    WSADATA data;  // 存储 Winsock 初始化信息
    // 初始化 Winsock 库，使用 2.2 版本
    int ret = WSAStartup(MAKEWORD(2, 2), &data);
    if (ret != 0) {  // 检查初始化是否成功
        error_die("WSAStartup");  // 初始化失败则调用错误处理函数
    }

    // 创建 TCP 流式套接字
    int server_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {  // 检查套接字创建是否成功
        error_die("套接字");  // 套接字创建失败则调用错误处理函数
    }

    int opt = 1;  // 设置套接字选项，使地址可复用
    // 设置套接字选项 SO_REUSEADDR
    ret = setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (ret == SOCKET_ERROR) {  // 检查套接字选项设置是否成功
        error_die("setsockopt");  // 套接字选项设置失败则调用错误处理函数
    }

    // 配置服务器端的网络地址结构
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));  // 清空地址结构
    server_addr.sin_family = AF_INET;  // 设置地址族为 IPv4
    server_addr.sin_port = htons(*port);  // 将端口号转换为网络字节序
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // 将 IP 地址设置为任意地址

    // 将套接字绑定到服务器地址
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        error_die("bind");  // 绑定失败则调用错误处理函数
    }

    int nameLen = sizeof(server_addr);  // 获取地址结构长度
    // 若端口为 0，则动态获取分配的端口号
    if (*port == 0) {
        if (getsockname(server_socket, (struct sockaddr*)&server_addr, &nameLen) == SOCKET_ERROR) {
            error_die("getsockname");  // 获取端口号失败则调用错误处理函数
        }
        *port = server_addr.sin_port;  // 更新端口号
    }

    // 开始监听客户端连接，监听队列长度为 5
    if (listen(server_socket, 5) == SOCKET_ERROR) {
        error_die("listen");  // 监听失败则调用错误处理函数
    }

    return server_socket;  // 返回服务器套接字
}

// 从指定的客户端套接字读取一行数据，保存到 buff 中
int get_line(int sock, char* buff, int size) {
    char c = 0;  // 存储读取的字符
    int i = 0;  // 存储已读取字符的数量
    // 循环读取字符，直到遇到换行符或缓冲区已满
    while (i < size - 1 && c != '\n') {
        // 从套接字读取一个字符
        int n = recv(sock, &c, 1, 0);
        if (n > 0) {  // 成功读取字符
            if (c == '\r') {  // 如果是回车符
                // 查看下一个字符是否为换行符
                recv(sock, &c, 1, MSG_PEEK);
                if (c == '\n') {  // 若是，则读取该换行符
                    recv(sock, &c, 1, 0);
                }
                else {  // 若不是，则将当前字符视为换行符
                    c = '\n';
                }
            }
            buff[i++] = c;  // 将字符存储到缓冲区
        }
        else {  // 未成功读取字符
            c = '\n';  // 视为遇到换行符
        }
    }
    buff[i] = 0;  // 字符串结尾添加 '\0'
    return i;  // 返回实际读取的字节数
}

// 向指定的套接字发送一个提示还没有实现的错误页面
void unimplement(int client) {
    // 构造 HTTP 501 未实现的响应消息
    const char* message = "HTTP/1.1 501 Not Implemented\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 21\r\n"
        "\r\n"
        "501 Not Implemented";
    // 发送错误消息
    send(client, message, strlen(message), 0);
}

// 向客户端发送 404 未找到的错误响应
void not_found(int client) {
    char buff[1024];  // 存储响应信息
    // 构造完整的 HTTP 404 响应消息
    snprintf(buff, sizeof(buff), "HTTP/1.1 404 Not Found\r\n"
        "Server: EronHttpd/1.0\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>404 Not Found</H1></BODY></HTML>");
    // 发送 404 响应消息
    send(client, buff, strlen(buff), 0);
}

// 向客户端发送 HTTP 200 OK 响应头
void headers(int client, const char* type) {
    char buff[1024];  // 存储响应头信息
    // 构造包含状态码 200 和内容类型的响应头
    snprintf(buff, sizeof(buff), "HTTP/1.1 200 OK\r\n"
        "Server: EronHttpd/1.0\r\n"
        "Content-Type: %s\r\n"
        "\r\n", type);
    // 发送响应头
    send(client, buff, strlen(buff), 0);
}

// 从文件读取数据并发送给客户端
void cat(int client, FILE* resource) {
    char buff[4096];  // 存储文件数据的缓冲区
    int count = 0;  // 记录已发送的字节数
    // 循环读取文件内容并发送
    while (1) {
        // 从文件读取数据
        int ret = fread(buff, sizeof(char), sizeof(buff), resource);
        if (ret <= 0) {  // 读取结束或出错
            break;
        }
        // 发送读取的数据
        send(client, buff, ret, 0);
        count += ret;  // 更新已发送字节数
    }
    // 打印已发送的字节数
    printf("一共发送[%d]字节给浏览器\n", count);
}

// 根据文件名后缀确定内容类型
const char* getHeadType(const char* fileName) {
    const char* ret = "text/html";  // 默认内容类型
    const char* p = strrchr(fileName, '.');  // 查找文件后缀
    if (!p) return ret;  // 未找到后缀则返回默认类型
    p++;  // 移动指针到后缀起始位置
    // 根据后缀确定内容类型
    if (!strcmp(p, "css")) ret = "text/css";
    else if (!strcmp(p, "jpg")) ret = "image/jpeg";
    else if (!strcmp(p, "png")) ret = "image/png";
    else if (!strcmp(p, "js")) ret = "application/x-javascript";
    return ret;  // 返回内容类型
}

// 处理客户端请求的文件服务
void server_file(int client, const char* fileName) {
    int numchars = 1;  // 存储读取行的字符数
    char buff[1024];  // 存储读取的行数据
    // 读取请求数据包的剩余数据行
    while (numchars > 0 && strcmp(buff, "\n")) {
        numchars = get_line(client, buff, sizeof(buff));  // 逐行读取
        PRINTF(buff);  // 打印读取的行
    }

    FILE* resource = NULL;  // 存储文件指针
    // 打开文件，对于 index.html 以文本模式打开，其他文件以二进制模式打开
    if (strcmp(fileName, "htdocs/index.html") == 0) {
        resource = fopen(fileName, "rb");
    }
    else {
        resource = fopen(fileName, "rb");
    }
    if (resource == NULL) {  // 文件不存在
        not_found(client);  // 发送 404 错误响应
    }
    else {
        // 发送文件响应头
        headers(client, getHeadType(fileName));
        // 发送文件内容
        cat(client, resource);
        printf("资源发送完毕！\n");  // 打印发送完成信息
        fclose(resource);  // 关闭文件
    }
}

// 处理用户请求的线程函数
DWORD WINAPI accept_request(LPVOID arg) {
    char buff[1024];  // 存储接收的请求数据
    // 获取客户端套接字
    int client = (SOCKET)arg;
    // 从客户端套接字读取一行请求数据
    int numchars = get_line(client, buff, sizeof(buff));
    PRINTF(buff);  // 打印读取的请求数据

    char method[255];  // 存储请求方法
    int j = 0, i = 0;  // 索引变量
    // 解析请求方法
    while (!isspace(buff[j]) && i < sizeof(method) - 1) {
        method[i++] = buff[j++];
    }
    method[i] = 0;  // 字符串结尾添加 '\0'
    PRINTF(method);  // 打印请求方法

    // 检查请求方法是否为 GET 或 POST
    if (_stricmp(method, "GET") && _stricmp(method, "POST")) {
        unimplement(client);  // 不支持的请求方法，发送 501 错误响应
        return 0;
    }

    char url[255];  // 存储请求的 URL
    i = 0;
    // 跳过请求行中的空格
    while (isspace(buff[j]) && j < sizeof(buff)) {
        j++;
    }
    // 解析请求的 URL
    while (!isspace(buff[j]) && i < sizeof(url) - 1 && j < sizeof(buff)) {
        url[i++] = buff[j++];
    }
    url[i] = 0;  // 字符串结尾添加 '\0'
    PRINTF(url);  // 打印请求的 URL

    char path[512] = "htdocs";  // 存储请求资源的文件路径
    // 拼接文件路径
    strncat(path, url, sizeof(path) - strlen(path) - 1);
    if (path[strlen(path) - 1] == '/') {  // 如果是目录，则添加 index.html
        strncat(path, "index.html", sizeof(path) - strlen(path) - 1);
    }
    PRINTF(path);  // 打印文件路径

    struct stat status;  // 存储文件状态信息
    // 获取文件状态
    if (stat(path, &status) == -1) {
        // 读取请求数据包的剩余数据行
        while (numchars > 0 && strcmp(buff, "\n")) {
            numchars = get_line(client, buff, sizeof(buff));
            PRINTF(buff);
        }
        not_found(client);  // 文件不存在，发送 404 错误响应
    }
    else {
        if ((status.st_mode & S_IFMT) == S_IFDIR) {  // 如果是目录
            strncat(path, "/index.html", sizeof(path) - strlen(path) - 1);  // 添加 index.html
        }
        // 处理文件服务
        server_file(client, path);
    }
    // 关闭客户端套接字
    closesocket(client);
    return 0;
}

int main(void) {
    unsigned short port = 2002;  // 服务器监听的端口号
    // 启动服务器，获取服务器套接字
    int server_sock = startup(&port);
    // 打印服务器启动信息
    printf("httpd 服务已经启动，正在监听 %d 端口.........\n", port);

    struct sockaddr_in client_addr;  // 存储客户端地址
    int client_addr_len = sizeof(client_addr);  // 客户端地址长度

    // 循环等待客户端连接
    while (1) {
        // 接受客户端连接
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_sock == INVALID_SOCKET) {  // 连接失败
            error_die("accept");  // 调用错误处理函数
        }

        unsigned int threadId;  // 存储线程标识符
        // 创建线程处理客户端请求
        _beginthreadex(NULL, 0, (unsigned int(__stdcall*)(void*))accept_request, (void*)client_sock, 0, &threadId);
    }
    // 关闭服务器套接字
    closesocket(server_sock);
    return 0;
}