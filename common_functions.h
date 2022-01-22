#ifndef COMMON_FUNCTIONS
#define COMMON_FUNCTIONS

#include <iostream>
#include <vector>

using namespace std;

string execute_command(char* command)
{
    FILE *fpipe;
    char c = 0;
    string output;

    if (0 == (fpipe = (FILE*)popen(command, "r")))
    {
        perror("popen() failed.");
        exit(EXIT_FAILURE);
    }

    while (fread(&c, sizeof(c), 1, fpipe))
    {
        output += c;
    }

    pclose(fpipe);

    return(output);
}

string string_to_raw(string const command_output)
{
   string ret = command_output;
   size_t position = ret.find('\n');
   if ( position != ret.npos )
   {
      ret.replace(position, 1, "\\n");  // 1 --> length of characters to replace with
   }
   else if ((position = ret.find('\r')) != ret.npos )
   {
       ret.replace(position, 1, "\\r");
   }
   else
   {
       return ret;
   }

   return string_to_raw(ret);
}

string* extract_service_path(string service_name)
{
    size_t pos = 0;
    string delimiter = "\\";
    string service_path = "";
    static string service_array[2];
    while ((pos = service_name.find(delimiter)) != string::npos)
    {
        if (service_path != "")
        {
            service_path += delimiter + service_name.substr(0, pos);                //substr(start, end)
        }
        else
        {
                service_path += service_name.substr(0, pos);
        }
        service_name.erase(0, pos + delimiter.length());    //erase(start, end)
    }
    service_array[0] = service_path;
    service_array[1] = service_name;

    return service_array;
}

string path_user_access(string service_path, int user=1)
{
    string access_command_string = "icacls \"" + service_path + "\"";
    char* access_command = &access_command_string[0];           // convert string to pointer char

    string access_check = execute_command(access_command);
    string access_check_raw = string_to_raw(access_check);      // convert string to raw string

    string regex_user;
    if (user == 1)
    {
        regex_user = (R"(Users:.+?\\n)");
    }
    else
    {
        regex_user = (R"(Everyone:.+?\\n)");
    }
    regex reg_expr (regex_user);

    smatch access_match;
    int i = 1;
    string path_user_perm_string = "";
    while (regex_search(access_check_raw, access_match, reg_expr))
    {
        path_user_perm_string += access_match.str();
        i++;
        access_check_raw = access_match.suffix().str();
    }

    if (path_user_perm_string.length() == 0)
    {
        path_user_perm_string = path_user_access(service_path, -1);
    }
    return(path_user_perm_string);
}

vector<string> path_extract_access(string pathnames_raw)
{
    regex reg_expr (R"(\w:\\[^,.\"]+?\.exe)");

    smatch match;
    int i = 1;
    string service_name;
    string service_path;
    string* service_array;
    string service;
    vector<string> pathlist_user_access;
    string path_user_permissions;

    while (regex_search(pathnames_raw, match, reg_expr))
    {
        service_name = match.str();

        // Extracts service_path and service_name
        service_array = extract_service_path(service_name);
        service_path = service_array[0];
        service_name = service_array[1];

        //Access in Service Path
        path_user_permissions = path_user_access(service_path);
        //cout << path_user_permissions << endl;

        if (path_user_permissions.find("(M)") != string::npos)
        {
            service = service_path + "\\" + service_name;
            pathlist_user_access.push_back(service);
        }

        i++;
        pathnames_raw = match.suffix().str();
    }

    return pathlist_user_access;
}

#endif // COMMON_FUNCTIONS
