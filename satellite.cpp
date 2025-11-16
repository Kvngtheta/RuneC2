#define _HAS_STD_BYTE 0  // Must be defined before any C++ headers to avoid std::byte conflicts

#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>
#include <vector>
#include <map>
#include <sstream>
#include <random>
#include <cstring>
#include "myfunctions.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

struct LocalAgent {
    std::string id;
    std::string hostname;
    std::string ip;
    std::string os;
    std::string user;
    int port;
    bool active;
};

struct LocalSession {
    std::string id;
    std::string agent_id;
    bool active;
};

struct LocalProject {
    std::string id;
    std::string name;
};

class SatelliteServer {
private:
    SOCKET team_socket;
    std::string team_server_ip;
    int team_server_port;
    std::string account_id;
    std::string api_key;
    bool connected;
    bool running;
    
    std::map<std::string, LocalAgent> local_agents;
    std::map<std::string, LocalSession> local_sessions;
    std::map<std::string, LocalProject> local_projects;
    std::mutex data_mutex;

public:
    SatelliteServer(const std::string& server_ip, int port, 
                   const std::string& acc_id, const std::string& key)
        : team_server_ip(server_ip), team_server_port(port),
          account_id(acc_id), api_key(key), connected(false), running(false) {}

    void printBanner() {
        std::cout << "\n";
        std::cout << "  |---------------------------------------------------|\n";
        std::cout << "  |          RuneC2 Satellite Server v1.0             |\n";
        std::cout << "  |---------------------------------------------------|\n\n";
    }

    bool connectToTeamServer() {
#ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cerr << "WSAStartup failed\n";
            return false;
        }
#endif

        team_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (team_socket == INVALID_SOCKET) {
            std::cerr << "[-] Socket creation failed\n";
            return false;
        }

        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(team_server_port);
        inet_pton(AF_INET, team_server_ip.c_str(), &server_addr.sin_addr);

        std::cout << "[*] Connecting to team server at " << team_server_ip 
                  << ":" << team_server_port << "...\n";

        if (connect(team_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
            std::cerr << "[-] Connection failed\n";
            close(team_socket);
            return false;
        }

        char buffer[4096];
        int bytes = recv(team_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            std::cerr << "[-] Failed to receive authentication prompt\n";
            close(team_socket);
            return false;
        }

        buffer[bytes] = '\0';
        if (std::string(buffer).find("AUTH_REQUIRED") == std::string::npos) {
            std::cerr << "[-] Unexpected server response\n";
            close(team_socket);
            return false;
        }

        std::string auth = account_id + ":" + api_key + "\n";
        send(team_socket, auth.c_str(), auth.length(), 0);

        bytes = recv(team_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            std::cerr << "[-] Authentication failed\n";
            close(team_socket);
            return false;
        }

        buffer[bytes] = '\0';
        if (std::string(buffer).find("AUTH_SUCCESS") == std::string::npos) {
            std::cerr << "[-] Authentication failed - Invalid credentials\n";
            close(team_socket);
            return false;
        }

        connected = true;
        std::cout << "[+] Successfully connected to team server!\n";
        std::cout << "[+] Satellite ID: " << account_id << "\n\n";

        return true;
    }

    void start() {
        printBanner();

        if (!connectToTeamServer()) {
            return;
        }

        running = true;

        std::thread receiver_thread(&SatelliteServer::receiveFromTeamServer, this);
        
        commandInterface();

        running = false;
        receiver_thread.join();
        
        close(team_socket);
#ifdef _WIN32
        WSACleanup();
#endif
    }

private:
    void receiveFromTeamServer() {
        char buffer[4096];
        
        while (running && connected) {
            int bytes = recv(team_socket, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) {
                std::cout << "\n[-] Lost connection to team server\n";
                connected = false;
                break;
            }

            buffer[bytes] = '\0';
            handleTeamServerMessage(std::string(buffer));
        }
    }

    void handleTeamServerMessage(const std::string& message) {
        std::istringstream iss(message);
        std::string cmd;
        iss >> cmd;

        if (cmd == "SYNC_AGENT") {
            std::cout << "[*] Syncing agent from another satellite\n";
        }
        else if (cmd == "SYNC_SESSION") {
            std::cout << "[*] Syncing session from another satellite\n";
        }
        else if (cmd == "SYNC_PROJECT") {
            std::cout << "[*] Syncing project from another satellite\n";
        }
    }

    std::string generateId(const std::string& prefix) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 15);
        
        std::stringstream ss;
        ss << prefix << "-";
        for (int i = 0; i < 8; i++) {
            ss << std::hex << dis(gen);
        }
        return ss.str();
    }

    void createAgent() {
        LocalAgent agent;
        agent.id = generateId("AGT");
        
        std::cout << "Enter hostname: ";
        std::getline(std::cin, agent.hostname);
        
        std::cout << "Enter IP: ";
        std::getline(std::cin, agent.ip);

        std::cout << "Enter port number: ";
        std::string port_str;
        std::getline(std::cin, port_str);
        agent.port = std::stoi(port_str);

        std::cout << "Enter OS: ";
        std::getline(std::cin, agent.os);
        
        std::cout << "Enter user: ";
        std::getline(std::cin, agent.user);

        agent.active = true;

        {
            std::lock_guard<std::mutex> lock(data_mutex);
            local_agents[agent.id] = agent;
        }

        // Start beaconing to the agent's HTTP server
        std::cout << "[*] Starting beacon to agent at " << agent.ip << ":" << agent.port << "\n";
        agentbeaconFunction(agent.ip, agent.port);

        if (connected) {
            std::ostringstream oss;
            oss << "AGENT_NEW " << agent.id << " " << agent.hostname << " " 
                << agent.ip << " " << agent.os << " " << agent.user << "\n";
            send(team_socket, oss.str().c_str(), oss.str().length(), 0);
        }

        std::cout << "[+] Agent created: " << agent.id << "\n";
    }

    void createSession() {
        if (local_agents.empty()) {
            std::cout << "[-] No agents available. Create an agent first.\n";
            return;
        }

        std::cout << "Available agents:\n";
        for (const auto& pair : local_agents) {
            std::cout << "  - " << pair.second.id << " (" << pair.second.hostname << ")\n";
        }

        std::string agent_id;
        std::cout << "Enter agent ID: ";
        std::getline(std::cin, agent_id);

        if (local_agents.find(agent_id) == local_agents.end()) {
            std::cout << "[-] Invalid agent ID\n";
            return;
        }

        LocalSession session;
        session.id = generateId("SES");
        session.agent_id = agent_id;
        session.active = true;

        {
            std::lock_guard<std::mutex> lock(data_mutex);
            local_sessions[session.id] = session;
        }

        if (connected) {
            std::ostringstream oss;
            oss << "SESSION_NEW " << session.id << " " << session.agent_id << "\n";
            send(team_socket, oss.str().c_str(), oss.str().length(), 0);
        }

        std::cout << "[+] Session created: " << session.id << "\n";
    }

    void createProject() {
        LocalProject project;
        project.id = generateId("PRJ");
        
        std::cout << "Enter project name: ";
        std::getline(std::cin, project.name);

        {
            std::lock_guard<std::mutex> lock(data_mutex);
            local_projects[project.id] = project;
        }

        if (connected) {
            std::ostringstream oss;
            oss << "PROJECT_NEW " << project.id << " " << project.name << "\n";
            send(team_socket, oss.str().c_str(), oss.str().length(), 0);
        }

        std::cout << "[+] Project created: " << project.name << "\n";
    }

    void commandInterface() {
        std::string command;
        std::cout << "Satellite> ";
        
        while (std::getline(std::cin, command)) {
            if (command.empty()) {
                std::cout << "Satellite> ";
                continue;
            }

            std::istringstream iss(command);
            std::string cmd;
            iss >> cmd;

            if (cmd == "help") {
                printHelp();
            }
            else if (cmd == "status") {
                std::cout << "\n|----------------------------------------------------|\n";
                std::cout << "|                 Satellite Status                     |\n";
                std::cout << "|------------------------------------------------------|\n";
                std::cout << "  Connection:  " << (connected ? "Connected" : "Disconnected") << "\n";
                std::cout << "  Account ID:  " << account_id << "\n";
                std::cout << "  Team Server: " << team_server_ip << ":" << team_server_port << "\n";
                std::cout << "|------------------------------------------------------|\n\n";
            }
            else if (cmd == "create_agent") {
                createAgent();
            }
            else if (cmd == "create_session") {
                createSession();
            }
            else if (cmd == "create_project") {
                createProject();
            }
            else if (cmd == "list_agents") {
                std::lock_guard<std::mutex> lock(data_mutex);
                std::cout << "\n|----------------------------------------------------|\n";
                std::cout << "|                    Local Agents                      |\n";
                std::cout << "|------------------------------------------------------|\n";
                for (const auto& pair : local_agents) {
                    const auto& agent = pair.second;
                    std::cout << "  ID:   " << agent.id << "\n";
                    std::cout << "  Host: " << agent.hostname << "\n";
                    std::cout << "  IP:   " << agent.ip << "\n";
                    std::cout << "  OS:   " << agent.os << "\n";
                    std::cout << "  User: " << agent.user << "\n";
                    std::cout << "  ----------------------------------------------------\n";
                }
                std::cout << "╚---------------------------╝\n\n";
            }
            else if (cmd == "list_sessions") {
                std::lock_guard<std::mutex> lock(data_mutex);
                std::cout << "\n|----------------------------------------------------|\n";
                std::cout << "|                   Local Sessions                     |\n";
                std::cout << "|------------------------------------------------------|\n";
                for (const auto& pair : local_sessions) {
                    const auto& session = pair.second;
                    std::cout << "  Session: " << session.id << "\n";
                    std::cout << "  Agent:   " << session.agent_id << "\n";
                    std::cout << "  Status:  " << (session.active ? "Active" : "Inactive") << "\n";
                    std::cout << "  ----------------------------------------------------\n";
                }
                std::cout << "╚---------------------------╝\n\n";
            }
            else if (cmd == "list_projects") {
                std::lock_guard<std::mutex> lock(data_mutex);
                std::cout << "\n|----------------------------------------------------|\n";
                std::cout << "|                   Local Projects                     |\n";
                std::cout << "|------------------------------------------------------|\n";
                for (const auto& pair : local_projects) {
                    const auto& project = pair.second;
                    std::cout << "  ID:   " << project.id << "\n";
                    std::cout << "  Name: " << project.name << "\n";
                    std::cout << "  ----------------------------------------------------\n";
                }
                std::cout << "╚---------------------------╝\n\n";
            }
            else if (cmd == "exit" || cmd == "quit") {
                std::cout << "Disconnecting from team server...\n";
                running = false;
                break;
            }
            else {
                std::cout << "Unknown command. Type 'help' for available commands.\n";
            }

            std::cout << "Satellite> ";
        }
    }

    void printHelp() {
        std::cout << "\n|--------------------------------------------------|\n";
        std::cout << "|              Satellite Server Commands             |\n";
        std::cout << "|----------------------------------------------------|\n";
        std::cout << "  status           - Show connection status\n";
        std::cout << "  create_agent     - Create new agent (syncs to team)\n";
        std::cout << "  create_session   - Create new session (syncs to team)\n";
        std::cout << "  create_project   - Create new project (syncs to team)\n";
        std::cout << "  list_agents      - List local agents\n";
        std::cout << "  list_sessions    - List local sessions\n";
        std::cout << "  list_projects    - List local projects\n";
        std::cout << "  help             - Show this help message\n";
        std::cout << "  exit             - Disconnect and exit\n";
        std::cout << "╚---------------------------╝\n\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cout << "Usage: " << argv[0] << " <team_ip> <team_port> <account_id> <api_key>\n";
        std::cout << "\nExample:\n";
        std::cout << "  " << argv[0] << " 127.0.0.1 5555 SAT-a1b2c3d4 your_api_key_here\n";
        return 1;
    }

    std::string server_ip = argv[1];
    int server_port = std::atoi(argv[2]);
    std::string account_id = argv[3];
    std::string api_key = argv[4];

    SatelliteServer satellite(server_ip, server_port, account_id, api_key);
    satellite.start();

    return 0;
}