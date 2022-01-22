import subprocess
import re

def vuln_user_permissions(service, path_user_permissions):
	for user_permission in path_user_permissions:
		if "M" in user_permission:
			print(f"{service} is vulnerable to service name impersonation!")
			break

def main():
	pathnames = subprocess.check_output("wmic service where \"startname like 'localsystem' and startmode like 'auto'\" get pathname",shell=True).decode()
	
	pathnames_list = re.findall(r"(.+)(\\.+.exe)", pathnames)
	for path, service_name in pathnames_list:
		path = path.replace("\"", "")
		access_check = subprocess.check_output(f"icacls \"{path}\"", shell=True).decode()
		path_user_permissions = re.findall(r"Users:(.+)", access_check)
		service = path + service_name

		if len(path_user_permissions)==0:
			path_user_permissions = re.findall(r"Everyone:(.+)", access_check)
			vuln_user_permissions(service, path_user_permissions)
		else:
			vuln_user_permissions(service, path_user_permissions)

if __name__ == '__main__':
	main()