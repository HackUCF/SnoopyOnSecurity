import paramiko
from paramiko.client import *
import concurrent.futures
import socket
import ipaddress


def run_as_root(command, password, client):
    command = command.replace("'", "\\'")
    stdin, stdout, stderr = client.exec_command(
        f'echo "{password}" | sudo -S bash -c \'{command}\'',
        get_pty=True)
    return stdin, stdout, stderr

def establish_connection(host: str, user: str, password: str):
    try:
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy)
        client.connect(
            host,
            username=user,
            password=password,
            timeout=1,
            allow_agent=False,
            look_for_keys=False,
        )
        return client
    except socket.timeout:
        return 0
    except paramiko.BadAuthenticationType:
        return 0
    except paramiko.AuthenticationException:
        return 0

def change_all_passwords(
    paramik_client: paramiko.SSHClient, password: str, newpass: str, ignoreusers: list[str]
) -> tuple[list[str], str]:
    err = ""
    excluded_users = ' | '.join(["grep -v \"{}\"".format(i) for i in ignoreusers])
    cmd = f"""pass={newpass} && for i in $(cut -d: -f1 /etc/shadow | """+ excluded_users+ """); do echo -e "$pass\\n$pass" | passwd $i && echo "$i,$pass" >> /tmp/pw.txt; done"""

    _, _, stderr = run_as_root(cmd, password, paramik_client)
    issues = stderr.read(size=None)
    if issues.decode("utf-8") != "":
        err = issues.decode("utf-8")

    _, stdout, _ = run_as_root("cat /tmp/pw.txt", newpass, paramik_client)

    csv = [i.decode("utf-8") for i in stdout.read(size=None).splitlines()]

    run_as_root("rm /tmp/pw.txt", newpass, paramik_client)

    return csv, err

def run_backups(
    paramik_client: paramiko.SSHClient, bk_folder_path: str, password: str
) -> str:
    err = ""
    cmd = "mkdir "+bk_folder_path+""" && cp -rp {/home,/etc,/var,/opt,/srv} """+bk_folder_path

    _, _, stderr = run_as_root(cmd, password, paramik_client)
    issues = stderr.read(size=None)
    if issues.decode("utf-8") != "":
        err = issues.decode("utf-8")

    # Inconsistent behavior!
    # run_as_root(
    #     "chattr +i -R "+bk_folder_path, password, paramik_client
    # )

    return err
 
def harden(ip: str, username: str, password: str, newPass: str, backupPath: str, ignoreusers: list[str]):
    client = establish_connection(ip, username, password)
    if not client:
        print(f"Failed to connect to {ip}")
        return
    print(f"Successfully connected to {ip}; hardening...")
    err1 = run_backups(client, backupPath, password)
    passwords, err2 = change_all_passwords(client, password, newPass, ignoreusers)
    print(f"Finished {ip}; stderr from backups is {err1} and from passwords is {err2}")
    with open(f"{ip}.csv","w") as f:
        f.writelines([p+"\n" for p in passwords])

def sanitize(newpass: str, ignoreusers: str, subnet: str, bk_folder_path: str) -> bool:
    res = True
    if newpass == "":
        print("You didn't define the new password.")
        res = False
    if ignoreusers == "":
        print("You didn't define any ignored users. (Hint: the script still works if the user doesn't actually exist.)")
        res = False
    if subnet == "":
        print("You didn't define the subnet.")
        res = False
    if bk_folder_path == "":
        print("You didn't define the backup folder.")
        res = False
    
    return res


def main():
    newpass = input("Enter the new password to set everything to: ")
    ignoreusers = input("Enter the comma-separated users to ignore (e.g. 'myfunuser,anotherguy,test'): ")
    subnet = input("Enter the subnet (e.g., 192.168.1.0/24): ")
    bk_folder_path = input("Enter the folder to backup to: ")
    if not sanitize(newpass, ignoreusers, subnet, bk_folder_path):
        return
    user = "ccdc"
    password = "ccdc"
    verbose = False
    workers = 10
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for host in ipaddress.ip_network(subnet, strict=False):
            # print(f"Connecting to {host}...")
            try:
                executor.submit(harden, str(host), user, password, newpass, bk_folder_path, ignoreusers.split(","))
            except:
                pass

if __name__ == "__main__":
    main()
