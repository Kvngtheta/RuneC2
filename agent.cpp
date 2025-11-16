#include "myfunctions.h"
#include <iostream>
using namespace std;
//this is a very basic agent implementation for testing purposes only
int main(){

string id = buildUniqueID();
char answer;
cout << "This will generate a unique id, once id is generated you will not be able to see raw data again. Are you sure you want to proceed? (y/n)\n";
cin >> answer;

if (answer == 'y'){
cout << "Unique ID: " << id << endl;
}
else{
    cout << "This will generate a unique id, once id is generated you will not be able to see raw data again. Are you sure you want to proceed? (y/n)\n";
    cin >> answer;
}

string host;
string endpoint;
string sendData;
int port;
char moreData;
char validate;

do{
//check unique id is still valid
string id2 = buildUniqueID();
if (id2 != id){
validate = 'n';
}
else{
    validate = 'y';
}

//this is temporary for testing purposes; this information will be passed manually on the backend
cout << "Enter server IP or domain (example: 192.168.1.20 or example.com): ";
cin >> host;
cout << "Enter API endpoint (example: /api/collect): ";
cin >> endpoint;
cout << "Enter server port (example: 80 or 443): ";
cin >> port;
cout << "Enter data to send: ";
cin.ignore();
getline(cin, sendData);


sendPostRequest(
        host,                           // example: "192.168.1.20" or "example.com"
        port,                           // port
        endpoint,                       // API path
        sendData,                       // custom data
        id,                              // unique ID
        validate                         // validation status
    );
    cout << "send more data? (y/n)\n";
    cin >> moreData;
} while (moreData == 'y');

cout << "Press any key to exit...\n";
cin.ignore();
cin.get();

return 0;



}