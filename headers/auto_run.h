#include <iostream>
#include "common_functions.h"

using namespace std;

int auto_run()
{
    cout << "[+] Looking for Auto-Run Programs" << endl;
    string startup_programs = execute_command("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    string startup_programs_raw = string_to_raw(startup_programs);

    vector<string> vuln_pathlist = path_extract_access(startup_programs_raw);
    for (auto vuln_path : vuln_pathlist)
    {
        cout << vuln_path + " is vulnerable to Auto-Run" << endl;
    }
    return 0;
}
