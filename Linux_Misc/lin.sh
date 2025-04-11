#!/bin/bash


echo -e "         _
        (:)_
      ,'    \`.
     :        :
     |        |              ___
     |       /|    ______   // _\\
     ; -  _,' :  ,'      \`. \\\\  -\\
    /          \\/          \\ \\\\  :
   (            :  ------.  \`-'  |
____\\___    ____|______   \\______|_______
        |::|           '--\`           SSt
        |::|
        |::|
        |::|
        |::;
        \`:/
"
echo -e "\033[34m[i] Snoopy on Security\033[0m"

echo -e "\033[34m[i] Running...\033[0m"

mkdir /.x84
cp -rp {/var/www,/etc,/home,/opt,/root} /.x84 &

rm -rf /root/.ssh/*
rm -rf /home/*/.ssh/authorized_keys
rm -f /root/.bashrc
rm -f /home/*/.bashrc

echo -e "\033[34m[i] Temporarily removed SSH Keys while initial verification takes place \033[0m"

#Setting a different password for every user, versus the same password for every user
cut -d: -f1 /etc/passwd|while read u;do p=$(tr -dc A-Za-z0-9 </dev/urandom|head -c4);echo $u:$u-$p|chpasswd;echo $u:$u-$p;done

echo -e "\033[34m[i] Set Password\033[0m"

sysctl fs.inotify.max_user_watches=524288

sed -i 's/#PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config

echo "Run this command to restart sshd: systemctl restart sshd"

echo -e "\033[34m[i] Installing security packages and removing scheduling tools\033[0m"
if command -v apt >/dev/null; then
    apt update
    apt install --reinstall openssh-server auditd ripgrep debsums libapache2-mod-security2 acl -y
    sudo apt -o Dpkg::Options::="--force-confmiss" install --reinstall libpam-modules -y
    apt remove --purge cron crontab at -y
    apt install --reinstall libpam-modules -y
elif command -v yum >/dev/null; then
    yum install policycoreutils-python auditd ripgrep mod_security mod_security_crs iptables -y
    yum install -y yum-utils
    yum-config-manager --add-repo=https://copr.fedorainfracloud.org/coprs/carlwgeorge/ripgrep/repo/epel-7/carlwgeorge-ripgrep-epel-7.repo
    yum install -y ripgrep
    sudo yum reinstall pam openssh-server -y
    yum remove cronie chrony cronie-noanacron at cronie-anacron crontabs -y
elif command -v pacman >/dev/null; then
    pacman -S --noconfirm --needed openssh audit pam acl apache-mod-security
    pacman -Rns --noconfirm cronie at
    pacman -S --noconfirm pam --needed
else
    echo "Error: No supported package manager found."
    exit 1
fi

echo -e "\033[34m[i] Removing unnecessary scheduling tools \033[0m"
# kill cron
killall cron
killall atd
killall crond
killall anacron


echo -e "\033[34m[i] Setting Audit Rules\033[0m"

auditctl -a exit,always -F arch=b64 -F euid=0 -S execve -k audit-wazuh-c
auditctl -a exit,always -F arch=b32 -F euid=0 -S execve -k audit-wazuh-c
auditctl -a exit,always -F arch=b64 -F euid!=0 -S execve -k audit-wazuh-c
auditctl -a exit,always -F arch=b32 -F euid!=0 -S execve -k audit-wazuh-c

echo -e "\033[34m[i] Setting Permissions\033[0m"
setfacl -m u:www-data:--- $(which bash) 2>/dev/null
setfacl -m u:www-data:--- $(which dash) 2>/dev/null
setfacl -m u:www-data:--- $(which sh) 2>/dev/null
setfacl -m u:www-data:--- $(which setfacl) 2>/dev/null
setfacl -m u:apache:--- $(which bash) 2>/dev/null
setfacl -m u:apache:--- $(which dash) 2>/dev/null
setfacl -m u:apache:--- $(which sh) 2>/dev/null
setfacl -m u:apache:--- $(which setfacl) 2>/dev/null



echo -e "\033[34m[i] Removing sudoedit to fix vulnerability\033[0m"

rm -f $(which sudoedit) 2>/dev/null

echo -e "\033[34m[i] Setting Permissions to fix vulnerability\033[0m"

chmod 0755 /usr/bin/pkexec 2>/dev/null

#Taking backup
command -v mysqldump >/dev/null && mysqldump -u root --all-databases > /.x84/db.sql && chmod 000 /.x84/db.sql
chattr +i /.x84 2>/dev/null

chattr +i /lib/x86_64-linux-gnu/security 2>/dev/null

#Security web directory from changes
chattr -R +i /var/www 2>/dev/null
