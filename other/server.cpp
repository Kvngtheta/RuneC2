#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define SOCKET int
    #define INVALID_SOCKET -2
    #define SOCKET_ERROR -2
#endif

// Data structures
struct Agent {
    std::string id;
    std::string hostname;
    std::string ip;
    std::string os;
    std::string user;
    std::string satellite_id;
    time_t last_seen;
    bool active;
};

struct Session {
    std::string id;
    std::string agent_id;
    std::string satellite_id;
    time_t created;
    bool active;
};

struct Project {
    std::string id;
    std::string name;
    std::string satellite_id;
    time_t created;
};

struct SatelliteAccount {
    std::string id;
    std::string name;
    std::string api_key;
    time_t created;
    bool active;
};

struct ConnectedSatellite {
    std::string account_id;
    SOCKET socket;
    std::string ip;
    time_t connected_time;
};

struct LogEntry {
    std::string timestamp;
    std::string satellite_id;
    std::string level;
    std::string message;
};

// Simple in-memory database
class Database {
private:
    std::map<std::string, Agent> agents;
    std::map<std::string, Session> sessions;
    std::map<std::string, Project> projects;
    std::map<std::string, SatelliteAccount> accounts;
    std::vector<LogEntry> logs;
    std::mutex db_mutex;

public:
    // Account management
    SatelliteAccount createAccount(const std::string& name) {
        std::lock_guard<std::mutex> lock(db_mutex);
        SatelliteAccount acc;
        acc.id = generateId("SAT");
        acc.name = name;
        acc.api_key = generateApiKey();
        acc.created = time(nullptr);
        acc.active = true;
        accounts[acc.id] = acc;
        return acc;
    }

    bool validateAccount(const std::string& account_id, const std::string& api_key) {
        std::lock_guard<std::mutex> lock(db_mutex);
        auto it = accounts.find(account_id);
        if (it != accounts.end() && it->second.api_key == api_key && it->second.active) {
            return true;
        }
        return false;
    }

    std::vector<SatelliteAccount> getAllAccounts() {
        std::lock_guard<std::mutex> lock(db_mutex);
        std::vector<SatelliteAccount> result;
        for (const auto& pair : accounts) {
            result.push_back(pair.second);
        }
        return result;
    }

    // Agent management
    void addAgent(const Agent& agent) {
        std::lock_guard<std::mutex> lock(db_mutex);
        agents[agent.id] = agent;
    }

    std::vector<Agent> getAllAgents() {
        std::lock_guard<std::mutex> lock(db_mutex);
        std::vector<Agent> result;
        for (const auto& pair : agents) {
            result.push_back(pair.second);
        }
        return result;
    }

    // Session management
    void addSession(const Session& session) {
        std::lock_guard<std::mutex> lock(db_mutex);
        sessions[session.id] = session;
    }

    std::vector<Session> getAllSessions() {
        std::lock_guard<std::mutex> lock(db_mutex);
        std::vector<Session> result;
        for (const auto& pair : sessions) {
            result.push_back(pair.second);
        }
        return result;
    }

    // Project management
    void addProject(const Project& project) {
        std::lock_guard<std::mutex> lock(db_mutex);
        projects[project.id] = project;
    }

    std::vector<Project> getAllProjects() {
        std::lock_guard<std::mutex> lock(db_mutex);
        std::vector<Project> result;
        for (const auto& pair : projects) {
            result.push_back(pair.second);
        }
        return result;
    }

    // Log management
    void addLog(const LogEntry& log) {
        std::lock_guard<std::mutex> lock(db_mutex);
        logs.push_back(log);
        if (logs.size() > 1000) {
            logs.erase(logs.begin());
        }
    }

    std::vector<LogEntry> getLogs(int limit = 50) {
        std::lock_guard<std::mutex> lock(db_mutex);
        int sz = static_cast<int>(logs.size());
        int start = sz - limit;
        if (start < 0) start = 0;
        return std::vector<LogEntry>(logs.begin() + start, logs.end());
    }

private:
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

    std::string generateApiKey() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 61);
        static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        
        std::string key;
        for (int i = 0; i < 32; i++) {
            key += charset[dis(gen)];
        }
        return key;
    }
};

class TeamServer {
private:
    Database db;
    std::map<std::string, ConnectedSatellite> connected_satellites;
    std::mutex satellites_mutex;
    SOCKET server_socket;
    bool running;
    int port;

public:
    TeamServer(int p = 5555) : running(false), port(p) {}

    void printAsciiArt() {
        std::cout << "\n";
        std::cout << "  ######╗ ##╗   ##╗###╗   ##╗#######╗ ######╗######╗ \n";
        std::cout << "  ##|--##╗##|   ##|####╗  ##|##|-╝##|-╝╚-##╗\n";
        std::cout << "  ######|╝##|   ##|##|##╗ ##|#####╗  ##|      #####|╝\n";
        std::cout << "  ##|--##╗##|   ##|##|╚##╗##|##|--╝  ##|      ╚---##╗\n";
        std::cout << "  ##|  ##|╚######|╝##| ╚####|#######╗╚######╗######|╝\n";
        std::cout << "  ╚-╝  ╚-╝ ╚--╝ ╚-╝  ╚---╝╚---╝ ╚--╝╚--╝ \n";
        std::cout << "\n";
        std::cout << "  -------------------------------\n";
        std::cout << "  Command - Collaborate - Connect\n";
        std::cout << "  -------------------------------\n\n";
    }

    void start() {
#ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cerr << "WSAStartup failed\n";
            return;
        }
#endif

        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket == INVALID_SOCKET) {
            std::cerr << "Socket creation failed\n";
            return;
        }

        int opt = 1;
        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
            std::cerr << "Bind failed\n";
            close(server_socket);
            return;
        }

        if (listen(server_socket, 10) == SOCKET_ERROR) {
            std::cerr << "Listen failed\n";
            close(server_socket);
            return;
        }

        running = true;
        printAsciiArt();
        std::cout << "[+] Team Server started on port " << port << "\n";
        std::cout << "[+] Waiting for satellite connections...\n\n";

        std::thread accept_thread(&TeamServer::acceptConnections, this);
        commandInterface();
        
        running = false;
        accept_thread.join();
        close(server_socket);

#ifdef _WIN32
        WSACleanup();
#endif
    }

private:
    void acceptConnections() {
        while (running) {
            sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            SOCKET client_socket = accept(server_socket, (sockaddr*)&client_addr, &client_len);

            if (client_socket != INVALID_SOCKET) {
                std::thread(&TeamServer::handleSatellite, this, client_socket, 
                           std::string(inet_ntoa(client_addr.sin_addr))).detach();
            }
        }
    }

    void handleSatellite(SOCKET client_socket, const std::string& ip) {
        char buffer[4096];
        
        // Authentication
        send(client_socket, "AUTH_REQUIRED\n", 14, 0);
        
        int bytes = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            close(client_socket);
            return;
        }
        
        buffer[bytes] = '\0';
        std::string auth_data(buffer);
        
        size_t delim = auth_data.find(':');
        if (delim == std::string::npos) {
            send(client_socket, "AUTH_FAILED\n", 12, 0);
            close(client_socket);
            return;
        }

        std::string account_id = auth_data.substr(0, delim);
        std::string api_key = auth_data.substr(delim + 1);
        api_key.erase(std::remove(api_key.begin(), api_key.end(), '\n'), api_key.end());

        if (!db.validateAccount(account_id, api_key)) {
            send(client_socket, "AUTH_FAILED\n", 12, 0);
            close(client_socket);
            std::cout << "[-] Authentication failed from " << ip << "\n";
            return;
        }

        send(client_socket, "AUTH_SUCCESS\n", 13, 0);

        ConnectedSatellite sat;
        sat.account_id = account_id;
        sat.socket = client_socket;
        sat.ip = ip;
        sat.connected_time = time(nullptr);

        {
            std::lock_guard<std::mutex> lock(satellites_mutex);
            connected_satellites[account_id] = sat;
        }

        std::cout << "[+] Satellite " << account_id << " connected from " << ip << "\n";
        logEvent(account_id, "INFO", "Satellite connected");

        // Handle satellite communication
        while (running) {
            bytes = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) break;

            buffer[bytes] = '\0';
            handleSatelliteMessage(account_id, std::string(buffer));
        }

        {
            std::lock_guard<std::mutex> lock(satellites_mutex);
            connected_satellites.erase(account_id);
        }

        close(client_socket);
        std::cout << "[-] Satellite " << account_id << " disconnected\n";
        logEvent(account_id, "INFO", "Satellite disconnected");
    }

    void handleSatelliteMessage(const std::string& sat_id, const std::string& message) {
        std::istringstream iss(message);
        std::string cmd;
        iss >> cmd;

        if (cmd == "AGENT_NEW") {
            Agent agent;
            agent.satellite_id = sat_id;
            iss >> agent.id >> agent.hostname >> agent.ip >> agent.os >> agent.user;
            agent.last_seen = time(nullptr);
            agent.active = true;
            db.addAgent(agent);
            broadcastToSatellites("SYNC_AGENT " + message);
            logEvent(sat_id, "INFO", "New agent: " + agent.id);
        }
        else if (cmd == "SESSION_NEW") {
            Session session;
            session.satellite_id = sat_id;
            iss >> session.id >> session.agent_id;
            session.created = time(nullptr);
            session.active = true;
            db.addSession(session);
            broadcastToSatellites("SYNC_SESSION " + message);
            logEvent(sat_id, "INFO", "New session: " + session.id);
        }
        else if (cmd == "PROJECT_NEW") {
            Project project;
            project.satellite_id = sat_id;
            iss >> project.id >> project.name;
            project.created = time(nullptr);
            db.addProject(project);
            broadcastToSatellites("SYNC_PROJECT " + message);
            logEvent(sat_id, "INFO", "New project: " + project.name);
        }
    }

    void broadcastToSatellites(const std::string& message) {
        std::lock_guard<std::mutex> lock(satellites_mutex);
        for (auto& pair : connected_satellites) {
            send(pair.second.socket, message.c_str(), message.length(), 0);
            send(pair.second.socket, "\n", 1, 0);
        }
    }

    void logEvent(const std::string& sat_id, const std::string& level, const std::string& msg) {
        LogEntry log;
        time_t now = time(nullptr);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        log.timestamp = timebuf;
        log.satellite_id = sat_id;
        log.level = level;
        log.message = msg;
        db.addLog(log);
    }

    void commandInterface() {
        std::string command;
        std::cout << "RuneC3> ";
        
        while (std::getline(std::cin, command)) {
            if (command.empty()) {
                std::cout << "RuneC3> ";
                continue;
            }

            std::istringstream iss(command);
            std::string cmd;
            iss >> cmd;

            if (cmd == "help") {
                printHelp();
            }
            else if (cmd == "create_account") {
                std::string name;
                iss >> name;
                if (!name.empty()) {
                    auto acc = db.createAccount(name);
                    std::cout << "\n[+] Account Created:\n";
                    std::cout << "    ID:      " << acc.id << "\n";
                    std::cout << "    Name:    " << acc.name << "\n";
                    std::cout << "    API Key: " << acc.api_key << "\n\n";
                } else {
                    std::cout << "Usage: create_account <name>\n";
                }
            }
            else if (cmd == "list_accounts") {
                auto accounts = db.getAllAccounts();
                std::cout << "\n|------------------------------------------------------|\n";
                std::cout << "|                   Satellite Accounts                 |\n";
                std::cout << "|------------------------------------------------------|\n";
                for (const auto& acc : accounts) {
                    std::cout << "  ID:   " << acc.id << "\n";
                    std::cout << "  Name: " << acc.name << "\n";
                    std::cout << "  Key:  " << acc.api_key << "\n";
                    
                }
                std::cout << "╚---------------╝\n\n";
            }
            else if (cmd == "list_satellites") {
                std::lock_guard<std::mutex> lock(satellites_mutex);
                std::cout << "\n|------------------------------------------------------|\n";
                std::cout << "|                 Connected Satellites                 |\n";
                std::cout << "|------------------------------------------------------|\n";
                for (const auto& pair : connected_satellites) {
                    std::cout << "  ID: " << pair.second.account_id << "\n";
                    std::cout << "  IP: " << pair.second.ip << "\n";
                    time_t duration = time(nullptr) - pair.second.connected_time;
                    std::cout << "  Uptime: " << duration / 3600 << "h " 
                             << (duration % 3600) / 60 << "m\n";
                    std::cout << "  -----------------─\n";
                }
                std::cout << "╚---------------╝\n\n";
            }
            else if (cmd == "list_agents") {
                auto agents = db.getAllAgents();
                std::cout << "\n-------------------------------------------------------|\n";
                std::cout << "|                     Active Agents                    |\n";
                std::cout << "|------------------------------------------------------|\n";
                for (const auto& agent : agents) {
                    std::cout << "  ID:       " << agent.id << "\n";
                    std::cout << "  Host:     " << agent.hostname << "\n";
                    std::cout << "  IP:       " << agent.ip << "\n";
                    std::cout << "  OS:       " << agent.os << "\n";
                    std::cout << "  User:     " << agent.user << "\n";
                    std::cout << "  Satellite: " << agent.satellite_id << "\n";
                    std::cout << "  -----------------─\n";
                }
                std::cout << "╚---------------╝\n\n";
            }
            else if (cmd == "list_sessions") {
                auto sessions = db.getAllSessions();
                std::cout << "\n|------------------------------------------------------|\n";
                std::cout << "|                   Active Sessions                    |\n";
                std::cout << "|------------------------------------------------------|\n";
                for (const auto& session : sessions) {
                    std::cout << "  Session ID: " << session.id << "\n";
                    std::cout << "  Agent ID:   " << session.agent_id << "\n";
                    std::cout << "  Satellite:  " << session.satellite_id << "\n";
                    std::cout << "  -----------------─\n";
                }
                std::cout << "----------------\n\n";
            }
            else if (cmd == "list_projects") {
                auto projects = db.getAllProjects();
                std::cout << "\n|------------------------------------------------------|\n";
                std::cout << "|                       Projects                       |\n";
                std::cout << "|------------------------------------------------------|\n";
                for (const auto& project : projects) {
                    std::cout << "  ID:        " << project.id << "\n";
                    std::cout << "  Name:      " << project.name << "\n";
                    std::cout << "  Satellite: " << project.satellite_id << "\n";
                    std::cout << "  -----------------─\n";
                }
                std::cout << "-----------------\n\n";
            }
            else if (cmd == "logs") {
                int limit = 20;
                iss >> limit;
                auto logs = db.getLogs(limit);
                std::cout << "\n|-----------------------------------------------------|\n";
                std::cout << "|                     Activity Logs                    |\n";
                std::cout << "|------------------------------------------------------|\n";
                for (const auto& log : logs) {
                    std::cout << "  [" << log.timestamp << "] "
                             << "[" << log.level << "] "
                             << "[" << log.satellite_id << "] "
                             << log.message << "\n";
                }
                std::cout << "╚---------------╝\n\n";
            }
            else if (cmd == "stats") {
                std::lock_guard<std::mutex> lock(satellites_mutex);
                std::cout << "\n|------------------------------------------------------|\n";
                std::cout << "|                   Server Statistics                  |\n";
                std::cout << "|------------------------------------------------------|\n";
                std::cout << "  Connected Satellites: " << connected_satellites.size() << "\n";
                std::cout << "  Total Agents:         " << db.getAllAgents().size() << "\n";
                std::cout << "  Active Sessions:      " << db.getAllSessions().size() << "\n";
                std::cout << "  Projects:             " << db.getAllProjects().size() << "\n";
                std::cout << "-----------------\n\n";
            }
            else if (cmd == "exit" || cmd == "quit") {
                std::cout << "Shutting down team server...\n";
                running = false;
                break;
            }
            else {
                std::cout << "Unknown command. Type 'help' for available commands.\n";
            }

            std::cout << "RuneC3> ";
        }
    }

    void printHelp() {
        std::cout << "\n|----------------------------------------------------|\n";
        std::cout << "|                  Available Commands                  |\n";
        std::cout << "|------------------------------------------------------|\n";
        std::cout << "  create_account <name>  - Create new satellite account\n";
        std::cout << "  list_accounts          - List all satellite accounts\n";
        std::cout << "  list_satellites        - List connected satellites\n";
        std::cout << "  list_agents            - List all agents\n";
        std::cout << "  list_sessions          - List all sessions\n";
        std::cout << "  list_projects          - List all projects\n";
        std::cout << "  logs [limit]           - View activity logs\n";
        std::cout << "  stats                  - Show server statistics\n";
        std::cout << "  help                   - Show this help message\n";
        std::cout << "  exit                   - Shutdown the server\n";
        std::cout << "-----------------------\n\n";
    }
};

int main(int argc, char* argv[]) {
    int port = 5555;
    
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }

    TeamServer server(port);
    server.start();

    return 0;
}