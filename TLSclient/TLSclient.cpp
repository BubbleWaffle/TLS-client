#pragma comment(lib, "libcurl_imp.lib")
#pragma comment(lib, "jsoncpp.lib")
#pragma comment(lib, "crypt32.lib")
#include <curl/curl.h>
#include <json/json.h>
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <ctime>
#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)

/*                            --CallBack function borrowed from--
https://stackoverflow.com/questions/9786150/save-curl-content-result-into-a-string-in-c */
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}
int main(int argc, char** argv) {
	const SSL_METHOD* method;
	SSL_CTX* ctx;

	/*--Create method and use it with context.--*/
	method = TLS_client_method();
	ctx = SSL_CTX_new(method);
	/*--Context validation.--*/
	if (ctx == 0) {
		printf("--Context failed!--\n");
		return 1;
	}
	/*--Use client certificate.--*/
	if (SSL_CTX_use_certificate_file(ctx, "klient.crt", SSL_FILETYPE_PEM) <= 0) {
		printf("--Client certificate failed!--\n");
		SSL_CTX_free(ctx);
		return 1;
	}
	/*--Use client private key.--*/
	if (SSL_CTX_use_PrivateKey_file(ctx, "klient.key", SSL_FILETYPE_PEM) <= 0) {
		printf("--Client key failed!--\n");
		SSL_CTX_free(ctx);
		return 1;
	}
	/*--Verify.--*/
	if (SSL_CTX_load_verify_locations(ctx, "ca.crt", nullptr) <= 0) {
		printf("--Verification failed!--\n");
		SSL_CTX_free(ctx);
		return 1;
	}

	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData); //Initialize winsock.

	if (iResult != 0) { 
		printf("--WSAStartup failed!--\n");
		SSL_CTX_free(ctx);
		return 1;
	}

	int sockfd = socket(AF_INET, SOCK_STREAM, 0); //Creat socket.

	if (sockfd == -1) {
		printf("--Socket failed!--\n");
		WSACleanup();
		SSL_CTX_free(ctx);
		return 1;
	}

	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_port = htons(6666);

	if (inet_pton(AF_INET, "127.0.0.1", &(server.sin_addr)) == -1) { 
		printf("--Binary conversion failed!--\n"); 
		closesocket(sockfd); 
		WSACleanup();
		SSL_CTX_free(ctx);
		return 1;
	}

	if (connect(sockfd, (struct sockaddr*)&server, sizeof(server)) == -1) {
		printf("--Connection failed!--\n");
		closesocket(sockfd);
		WSACleanup();
		SSL_CTX_free(ctx);
		return 1;
	}

	SSL* ssl = SSL_new(ctx); //Creating an encryption object.

	if (ssl == 0) {
		printf("--SSL failed!--!\n");
		closesocket(sockfd);
		WSACleanup();
		SSL_CTX_free(ctx);
		return 1;
	}
	/*--Descriptor assignment.--*/
	if (SSL_set_fd(ssl, sockfd) <= 0) {
		printf("--Setting fd failed!--\n");
		closesocket(sockfd);
		WSACleanup();
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		return 1;
	}
	/*--Connection encryption.--*/
	if (SSL_connect(ssl) == -1) {
		printf("--SSL connect failed!--\n");
		closesocket(sockfd);
		WSACleanup();
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		return 1;
	}

	CURL* curl;
	CURLcode res;
	Json::Reader reader;
	Json::Value js;
	std::string readBuffer;
	std::string text;

	curl = curl_easy_init(); //CURL session start.
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, "https://api.open-meteo.com/v1/forecast?latitude=49.82&longitude=19.05&current_weather=true");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

		res = curl_easy_perform(curl); //Request execution.
		if (res != CURLE_OK) printf("--CURL failed!--\n");

		/*--Parse JSON.--*/
		if (reader.parse(readBuffer, js)) {
			js = js.get("current_weather", "null");
			/*--Checking if data exists.--*/
			if (js == "null") {
				printf("Brak danych do odebrania!\n");
				SSL_shutdown(ssl);
				closesocket(sockfd);
				WSACleanup();
				SSL_free(ssl);
				SSL_CTX_free(ctx);
				curl_easy_cleanup(curl);
				return 1;
			}
		}

		text = js.toStyledString();
		const char* cJS = text.c_str();
		int size = text.size();
		int send = SSL_write(ssl, cJS, size); //Send data.

		if (send == -1 || send == 0) {
			printf("--Sending failed!--\n");
			SSL_shutdown(ssl);
			closesocket(sockfd);
			WSACleanup();
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			curl_easy_cleanup(curl);
			return 1;
		}
		SSL_shutdown(ssl);
		printf("--Data sent!--\n");
		curl_easy_cleanup(curl);
	}

	closesocket(sockfd);
	WSACleanup();
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	return 0;
}