#!/bin/sh
domain="teste.com.br"
nameserver="IP_DNS"
dominio="TESTE"

echo -n "dns-nameservers $nameserver" >> /etc/network/interfaces
localectl set-locale LANG=pt_BR.iso88591
###DEBIAN START AD
apt -y install realmd sssd sssd-tools adcli krb5-user packagekit samba-common samba-common-bin samba-libs resolvconf sudo vim
systemctl restart ifup@ens192 resolvconf
echo -n "session     optional      pam_mkhomedir.so skel=/etc/skel umask=077" >> /etc/pam.d/common-session
realm discover $domain
echo -n "Digite usuario: "
read admin_user
echo -n "Digite a senha: "
read passwd
echo -n $passwd | realm join $domain -U $admin_user

template=$(cat <<EOF
[sssd]\ndomains = $domain\nconfig_file_version = 2\nservices = nss, pam\n\n[domain/$domain]\nad_domain = $domain\nkrb5_realm = $dominio\nrealmd_tags = manages-system joined-with-samba\ncache_credentials = True\nid_provider = ad\nkrb5_store_password_if_offline = True\ndefault_shell = /bin/bash\nldap_id_mapping = True\nuse_fully_qualified_names = False\nfallback_homedir = /home/%d/%u\naccess_provider = ad\n
EOF
)
echo "$template" > /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf

systemctl restart sssd
id $admin_user
systemctl enable sssd
echo -n "AllowGroups linuxadmins" >> /etc/ssh/sshd_config 
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/resolv.conf
echo -n "%linuxadmins      ALL=(ALL)   ALL" >> /etc/sudoers
/etc/init.d/ssh restart
echo -n exit | su - $admin_user