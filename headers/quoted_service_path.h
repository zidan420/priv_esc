#include <iostream>
#include <string>
#include <regex>
#include "common_functions.h"

using namespace std;

int qsp()
{
    //1. Find all LOCALSYSTEM service with automatic mode to fetch PATHNAME only
    string pathnames, pathnames_raw;

    cout << "\n[+] Using WMIC to fetch services" << endl;
    //wmic service get displayname,name,pathname,startmode, startname
    pathnames = execute_command("wmic service where 'startname like \"localsystem\" and startmode like \"auto\"' get pathname");
    pathnames_raw = string_to_raw(pathnames);

    // For Windows 11 or versions where wmic is NOT installed
    if (pathnames_raw.length() == 0)
    {
        cout << "\n[+] Using WMI to fetch services" << endl;
        //powershell -command "Get-WmiObject Win32_Service | where StartName -eq 'LocalSystem' | where startmode -eq 'auto' | select pathname"
        pathnames = execute_command("powershell -command \"Get-WmiObject Win32_Service | where StartName -eq 'LocalSystem' | where startmode -eq 'auto' | select pathname\"");
        pathnames_raw = string_to_raw(pathnames);
        //cout << pathnames_raw << endl;
    }

    //2. Check for access in service path
    vector<string> vuln_pathlist = path_extract_access(pathnames_raw);
    for (auto vuln_path : vuln_pathlist)
    {
        cout << vuln_path + " is vulnerable to service name impersonation!" << endl;
    }
    //3. If service is already running, and then rename the service to sth else (as you can't overwrite it)
    //4. Drop a reverse shell with the same service name
    //5. Restart the pc with "shutdown /r"
    //6. Connect to reverse shell with netcat

    return(0);
}
