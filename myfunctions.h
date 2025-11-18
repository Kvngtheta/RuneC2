#pragma once
#include <string>
#include <iostream>
#include <thread>
#include <chrono>

std::string buildUniqueID();

bool sendPostRequest(const std::string& host, int port, const std::string& path, 
                     const std::string& customData, const std::string& uniqueID, char validate);

void agentbeaconFunction(const std::string& ip, int port);
