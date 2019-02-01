#!/bin/sh
domain="teste.com.br"
nameserver="IP_DNS"
dominio="TESTE"

yum install epel-release -y
yum install vim ntpdate screen less unzip bzip2 multitail htop nmap tcpdump rsync traceroute iptraf iperf git mercurial bzr subversion net-tools -y
yum groupinstall "Development Tools" -y
localectl set-locale LANG=pt_BR.iso88591
yum install adcli.x86_64 samba-common oddjob-mkhomedir oddjob samba-winbind-clients samba-winbind sssd -y 
sed -i '/NetworkManager/a search '$domain'\nnameserver '$nameserver'' /etc/resolv.conf
authconfig --enablekrb5 --krb5kdc=$domain --krb5adminserver=$domain --krb5realm=$dominio --enablesssd --enablesssdauth --update 
echo -n "Digite usuario: "
read admin_user
echo -n "Digite a senha: "
read -s passwd
echo -n $passwd | adcli join $domain -U $admin_user --stdin-password
touch /etc/sssd/sssd.conf
template=$(cat <<EOF
[sssd]\ndomains = $domain\nconfig_file_version = 2\nservices = nss, pam\n\n[domain/$domain]\nad_domain = $domain\nkrb5_realm = $dominio\nrealmd_tags = manages-system joined-with-samba\ncache_credentials = True\nid_provider = ad\nkrb5_store_password_if_offline = True\ndefault_shell = /bin/bash\nldap_id_mapping = True\nuse_fully_qualified_names = False\nfallback_homedir = /home/%d/%u\naccess_provider = ad\n
EOF
)
echo -e $template > /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
echo -n "session     optional      pam_mkhomedir.so skel=/etc/skel umask=077" >> /etc/pam.d/system-auth
service sssd start 
service winbind start
id $admin_user
systemctl enable sssd
systemctl enable winbind
echo -n "AllowGroups linuxadmins" >> /etc/ssh/sshd_config 
echo -n "%linuxadmins      ALL=(ALL)   ALL" >> /etc/sudoers
echo -n exit | su - $admin_user
yum install pam_krb5.x86_64 -y
