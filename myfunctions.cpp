#define _HAS_STD_BYTE 0  // Disable std::byte to avoid conflicts with Windows headers
#include <ws2tcpip.h>
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <iostream>

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")

std::string getMacAddress() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD buflen = sizeof(adapterInfo);

    if (GetAdaptersInfo(adapterInfo, &buflen) != ERROR_SUCCESS)
        return "";

    PIP_ADAPTER_INFO pAdapter = adapterInfo;

    char mac[18];
    sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
        pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2],
        pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5]
    );

    return mac;
}

std::string getLocalIP() {
    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    addrinfo hints = {};
    hints.ai_family = AF_INET;
    addrinfo* info = nullptr;

    if (getaddrinfo(hostname, nullptr, &hints, &info) != 0)
        return "";

    char ip[INET_ADDRSTRLEN];
    sockaddr_in* addr = (sockaddr_in*)info->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));

    freeaddrinfo(info);
    return ip;
}

std::string getComputerName() {
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer);
    GetComputerNameA(buffer, &size);
    return buffer;
}

std::string base64Encode(const std::string& input) {
    DWORD encodedLen = 0;

    CryptBinaryToStringA(
        (BYTE*)input.data(),
        input.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        nullptr,
        &encodedLen
    );

    std::string out(encodedLen, '\0');

    CryptBinaryToStringA(
        (BYTE*)input.data(),
        input.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        const_cast<char*>(out.data()),  // Cast away const for Windows API
        &encodedLen
    );

    return out;
}

std::string sha256(const std::string& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];
    DWORD hashLen = 32;

    CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)data.data(), data.size(), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

    std::ostringstream ss;
    for (int i = 0; i < 32; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return ss.str();
}

std::string buildUniqueID() {
    std::string mac = getMacAddress();
    std::string ip  = getLocalIP();
    std::string host = getComputerName();

    // Build string: mac-ip-host
    std::string combined = mac + "-" + ip + "-" + host;

    // Base64 encode
    std::string b64 = base64Encode(combined);

    // SHA256 hash
    std::string hash = sha256(b64);

    return hash;
}

bool sendPostRequest(const std::string& host, int port, const std::string& path, 
                     const std::string& customData, const std::string& uniqueID, char validate)
{
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    
    // Start Winsock
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
        return false;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
        return false;

    // Resolve hostname
    struct hostent* he = gethostbyname(host.c_str());
    if (he == NULL)
        return false;

    // Fill server struct
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    memcpy(&server.sin_addr, he->h_addr, he->h_length);

    // Connect
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0)
        return false;

    // JSON Body (edit if needed)
    std::string body = 
        "{\r\n"
        "  \"unique_id\": \"" + uniqueID + "\",\r\n"
        "  \"data\": \"" + customData + "\",\r\n"
        "  \"validate\": \"" + validate + "\"\r\n"
        "}";

    // Build HTTP Request
    std::string request =
        "POST " + path + " HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" +
        body;

    // Send request
    send(sock, request.c_str(), request.size(), 0);

    // Receive server response (optional)
    char buffer[1024];
    int bytesReceived;
    std::string response;

    while ((bytesReceived = recv(sock, buffer, sizeof(buffer), 0)) > 0)
        response.append(buffer, bytesReceived);

    closesocket(sock);
    WSACleanup();

    std::cout << "Server Response:\n" << response << std::endl;

    return true;
}