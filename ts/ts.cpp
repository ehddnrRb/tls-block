#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#endif // __linux
#ifdef WIN32
#include <ws2tcpip.h>
#endif // WIN32
#include <thread>

#ifdef WIN32
void myerror(const char* msg) { fprintf(stderr, "%s %lu\n", msg, GetLastError()); }
#else
void myerror(const char* msg) { fprintf(stderr, "%s %s %d\n", msg, strerror(errno), errno); }
#endif

void usage() {
	printf("tcp server %s\n",
#include "../version.txt"
   );
	printf("\n");
	printf("syntax: ts <port> [-e] [-si <src ip>] [-kaidle <keepalive idle> -kaintv <keepalive interval> -kacnt <keepalive count>]\n");
	printf("  -e : echo\n");
	printf("sample: ts 1234 -kidle 60\n");
}

struct Param {
	bool echo{false};
	uint16_t port{0};
	uint32_t srcIp{0};
	struct KeepAlive {
		int idle_{0};
		int interval_{1};
		int count_{10};
	} keepAlive_;

	bool parse(int argc, char* argv[]) {
		for (int i = 1; i < argc;) {
			if (strcmp(argv[i], "-e") == 0) {
				echo = true;
				i++;
				continue;
			}

			if (strcmp(argv[i], "-si") == 0) {
				int res = inet_pton(AF_INET, argv[i + 1], &srcIp);
				switch (res) {
					case 1: break;
					case 0: fprintf(stderr, "not a valid network address\n"); return false;
					case -1: myerror("inet_pton"); return false;
				}
				i += 2;
				continue;
			}

			if (strcmp(argv[i], "-kaidle") == 0) {
				keepAlive_.idle_ = atoi(argv[i + 1]);
				i += 2;
				continue;
			}

			if (strcmp(argv[i], "-kaintv") == 0) {
				keepAlive_.interval_ = atoi(argv[i + 1]);
				i += 2;
				continue;
			}

			if (strcmp(argv[i], "-kacnt") == 0) {
				keepAlive_.count_ = atoi(argv[i + 1]);
				i += 2;
				continue;
			}

			if (i < argc) port = atoi(argv[i++]);
		}
		return port != 0;
	}
} param;

void recvThread(int sd) {
	printf("connected\n");
	fflush(stdout);
	static const int BUFSIZE = 65536;
	char buf[BUFSIZE];
	while (true) {
		ssize_t res = ::recv(sd, buf, BUFSIZE - 1, 0);
		if (res == 0 || res == -1) {
			fprintf(stderr, "recv return %zd", res);
			myerror(" ");
			break;
		}
		buf[res] = '\0';
		printf("%s", buf);
		fflush(stdout);
		if (param.echo) {
			res = ::send(sd, buf, res, 0);
			if (res == 0 || res == -1) {
				fprintf(stderr, "send return %zd", res);
				myerror(" ");
				break;
			}
		}
	}
	printf("disconnected\n");
	fflush(stdout);
	::close(sd);
}

#ifdef WIN32
// declared in w2ipdef.h
#define TCP_KEEPALIVE       	 3
#define TCP_KEEPCNT              16
#define TCP_KEEPIDLE             TCP_KEEPALIVE
#define TCP_KEEPINTVL            17
#endif // WIN32

int main(int argc, char* argv[]) {
	if (!param.parse(argc, argv)) {
		usage();
		return -1;
	}

#ifdef WIN32
	WSAData wsaData;
	WSAStartup(0x0202, &wsaData);
#endif // WIN32

	//
	// socket
	//
	int sd = ::socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		myerror("socket");
		return -1;
	}

#ifdef __linux__
	//
	// setsockopt
	//
	{
		int optval = 1;
		int res = ::setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
		if (res == -1) {
			myerror("setsockopt");
			return -1;
		}
	}
#endif // __linux

	//
	// bind
	//
	{
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = param.srcIp;
		addr.sin_port = htons(param.port);

		ssize_t res = ::bind(sd, (struct sockaddr *)&addr, sizeof(addr));
		if (res == -1) {
			myerror("bind");
			return -1;
		}
	}

	//
	// listen
	//
	{
		int res = ::listen(sd, 5);
		if (res == -1) {
			myerror("listen");
			return -1;
		}
	}

	while (true) {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		int newsd = ::accept(sd, (struct sockaddr *)&addr, &len);
		if (newsd == -1) {
			myerror("accept");
			break;
		}

		//
		// keepalive
		//
		if (param.keepAlive_.idle_ != 0) {
			int optval = 1;
			if (::setsockopt(newsd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&optval, sizeof(int)) < 0) {
				myerror("setsockopt(SO_KEEPALIVE)");
				return -1;
			}

			if (::setsockopt(newsd, IPPROTO_TCP, TCP_KEEPIDLE, (const char*)&param.keepAlive_.idle_, sizeof(int)) < 0) {
				myerror("setsockopt(TCP_KEEPIDLE)");
				return -1;
			}

			if (::setsockopt(newsd, IPPROTO_TCP, TCP_KEEPINTVL, (const char*)&param.keepAlive_.interval_, sizeof(int)) < 0) {
				myerror("setsockopt(TCP_KEEPINTVL)");
				return -1;
			}

			if (::setsockopt(newsd, IPPROTO_TCP, TCP_KEEPCNT, (const char*)&param.keepAlive_.count_, sizeof(int)) < 0) {
				myerror("setsockopt(TCP_KEEPCNT)");
				return -1;
			}
		}

		std::thread* t = new std::thread(recvThread, newsd);
		t->detach();
	}
	::close(sd);
}
