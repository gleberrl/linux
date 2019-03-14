#!/bin/sh

######CAPTURA DE DADOS
IP=`cat /etc/sysconfig/network-scripts/ifcfg-e* | grep IPADDR | cut -d"=" -f2`
IP_TEST=`echo $IP | grep \"`

if [[ $IP_TEST == "" ]]; then
IP=`echo $IP`
else
IP=`echo $IP | cut -d"\"" -f2- | cut -d"\"" -f1`
fi

echo -e "\n\n########################################\nDigite a sigla da localidade que o Elasticsearch sera instalado:\nExemplo: Manaus -> sbeg\n\nLocalidade:"
read -r LOCALIDADE
NUM="01"
FOLDER_EXISTS=`ls -l /log | grep total | cut -d" " -f1`

if [[ $FOLDER_EXISTS == "total" ]];then
	EL_PATH="/log/elasticsearch"
	EL_LOG_PATH="/log/elasticsearch"
	EL_PATH_CODE=1
else
        EL_PATH="/var/lib/elasticsearch"
	EL_LOG_PATH="/var/log/elasticsearch"
        EL_PATH_CODE=2
fi

LOCALIDADE_M=`echo $LOCALIDADE | tr '[a-z]' '[A-Z]'`
LOCALIDADE_m=`echo $LOCALIDADE | tr '[A-Z]' '[a-z]'`

echo -e "\n\n#########################################\n\nLocalidade de instalacao: $LOCALIDADE_M\nPATH Base de Dados: $EL_PATH\nPATH Logs: $EL_LOG_PATH\n\n########################################"

sleep 3
TEMPLATE_ELASTICSEARCH_YML=$(cat <<TEMPLATE
## ======================== Elasticsearch Configuration =========================\n
#\n
# NOTE: Elasticsearch comes with reasonable defaults for most settings.\n
#       Before you set out to tweak and tune the configuration, make sure you\n
#       understand what are you trying to accomplish and the consequences.\n
#\n
# The primary way of configuring a node is via this file. This template lists\n
# the most important settings you may want to configure for a production cluster.\n
#\n
# Please consult the documentation for further information on configuration options:\n
# https://www.elastic.co/guide/en/elasticsearch/reference/index.html\n
#\n
# ---------------------------------- Cluster -----------------------------------\n
#\n
# Use a descriptive name for your cluster:\n
#\n
cluster.name: INFRAERO-$LOCALIDADE_M\n
#\n
# ------------------------------------ Node ------------------------------------\n
#\n
# Use a descriptive name for the node:\n
#\n
node.name: $LOCALIDADE_M$NUM\n
#\n
# Add custom attributes to the node:\n
#\n
#node.attr.rack: r1\n
#\n
# ----------------------------------- Paths ------------------------------------\n
#\n
# Path to directory where to store the data (separate multiple locations by comma):\n
#\n
path.data: $EL_PATH\n
#\n
# Path to log files:\n
#\n
path.logs: $EL_LOG_PATH\n
#\n
# ----------------------------------- Memory -----------------------------------\n
#\n
# Lock the memory on startup:\n
#\n
#bootstrap.memory_lock: true\n
#\n
# Make sure that the heap size is set to about half the memory available\n
# on the system and that the owner of the process is allowed to use this\n
# limit.\n
#\n
# Elasticsearch performs poorly when the system is swapping the memory.\n
#\n
# ---------------------------------- Network -----------------------------------\n
#\n
# Set the bind address to a specific IP (IPv4 or IPv6):\n
#\n
network.host: $IP\n
#\n
# Set a custom port for HTTP:\n
#\n
http.port: 9200\n
#\n
# For more information, consult the network module documentation.\n
#\n
# --------------------------------- Discovery ----------------------------------\n
#\n
# Pass an initial list of hosts to perform discovery when new node is started:\n
# The default list of hosts is ["127.0.0.1", "[::1]"]\n
#\n
discovery.zen.ping.unicast.hosts: ["$IP"]\n
#\n
# Prevent the "split brain" by configuring the majority of nodes (total number of master-eligible nodes / 2 + 1):\n
#\n
discovery.zen.minimum_master_nodes: 1\n
#\n
# For more information, consult the zen discovery module documentation.\n
#\n
# ---------------------------------- Gateway -----------------------------------\n
#\n
# Block initial recovery after a full cluster restart until N nodes are started:\n
#\n
#gateway.recover_after_nodes: 3\n
#\n
# For more information, consult the gateway module documentation.\n
#\n
# ---------------------------------- Various -----------------------------------\n
#\n
# Require explicit names when deleting indices:\n
#\n
#action.destructive_requires_name: true\n
thread_pool.search.size: 400\n
thread_pool.search.queue_size: 40000\n
path.repo: ["$EL_PATH/backups"]\n
TEMPLATE
)
TEMPLATE_ELASTICSEARCH_CRONTAB=$(cat <<TEMPLATE
#SHELL=/bin/bash\n
PATH=/sbin:/bin:/usr/sbin:/usr/bin\n
MAILTO=root\n\n

# For details see man 4 crontabs\n\n

# Example of job definition:\n
# .---------------- minute (0 - 59)\n
# |  .------------- hour (0 - 23)\n
# |  |  .---------- day of month (1 - 31)\n
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...\n
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat\n
# |  |  |  |  |\n
# \*  \*  \*  \*  \* user-name  command to be executed\n
##EXCLUIR INDEX DE PROXY COM MAIS DE 180 DIAS\n
0 1 1 8 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.01/'\n
0 1 1 8 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.02/'\n
0 1 1 8 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.03/'\n
0 1 1 8 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.04/'\n
0 1 1 9 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.05/'\n
0 1 1 9 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.06/'\n
0 1 1 9 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.07/'\n
0 1 1 9 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.08/'\n
0 1 1 10 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.10/'\n
0 1 1 10 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.11/'\n
0 1 1 10 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.12/'\n
0 1 1 10 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.13/'\n
0 1 1 11 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.14/'\n
0 1 1 11 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.15/'\n
0 1 1 11 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.16/'\n
0 1 1 11 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.17/'\n
0 1 1 12 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.18/'\n
0 1 1 12 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.19/'\n
0 1 1 12 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.20/'\n
0 1 1 12 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.21/'\n
0 1 1 1 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.22/'\n
0 1 1 1 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.23/'\n
0 1 1 1 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.24/'\n
0 1 1 1 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.25/'\n
0 1 1 2 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.26/'\n
0 1 1 2 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.27/'\n
0 1 1 2 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.28/'\n
0 1 1 2 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.29/'\n
0 1 1 3 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.30/'\n
0 1 1 3 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.31/'\n
0 1 1 3 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.32/'\n
0 1 1 3 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.33/'\n
0 1 1 4 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.34/'\n
0 1 1 4 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.35/'\n
0 1 1 4 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.36/'\n
0 1 1 4 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.37/'\n
0 1 1 5 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.38/'\n
0 1 1 5 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.39/'\n
0 1 1 5 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.40/'\n
0 1 1 5 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.41/'\n
0 1 1 6 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.42/'\n
0 1 1 6 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.43/'\n
0 1 1 6 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.44/'\n
0 1 1 6 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.45/'\n
0 1 1 7 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.46/'\n
0 1 1 7 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.47/'\n
0 1 1 7 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.48/'\n
0 1 1 7 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.49/'\n
0 1 1 7 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.50/'\n
0 1 1 7 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.51/'\n
0 1 1 7 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.52/'\n
0 1 1 7 \* root curl -XDELETE 'http://$IP:9200/logstash-proxy-*.53/'\n
TEMPLATE
)

TEMPLATE_SNMPD_CONF=$(cat <<TEMPLATE
##       sec.name  source          community\n
com2sec SEDEuser  10.0.17.70       cnsede\n
com2sec SEDEuser  10.0.17.89       cnsede\n
com2sec SEDEuser  10.0.17.102      cnsede\n
com2sec SEDEuser  10.0.27.141      cnsede\n\n

#       groupName      securityModel securityName\n
group   SEDEgroup v1            SEDEuser\n
group   SEDEgroup v2c           SEDEuser\n\n

#       name           incl/excl     subtree         mask(optional)\n
view    SEDE_v included .1\n\n

#       group          context sec.model sec.level prefix read   write  notif\n
access  SEDEgroup ""      any       noauth    exact  SEDE_v none none\n\n

# -----------------------------------------------------------------------------\n\n

syslocation SEDE\n
syscontact Equipe Servidores\n
TEMPLATE
)


instalacao () {
######INSTALACAO DE PACOTES
yum install -y epel-release
yum upgrade -y
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
echo -e "[elasticsearch-6.x]\nname=Elasticsearch repository for 6.x packages\nbaseurl=https://artifacts.elastic.co/packages/6.x/yum\ngpgcheck=1\ngpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch\nenabled=1\nautorefresh=1\ntype=rpm-md" > /etc/yum.repos.d/elasticsearch.repo

yum install -y java-1.8.0-openjdk.x86_64 elasticsearch vim ntpdate screen less unzip bzip2 multitail htop nmap tcpdump rsync traceroute iptraf iperf wget lsof net-tools
yum groupinstall -y "Development Tools"
systemctl enable elasticsearch.service
}

configuracao () {
######CONFIGURACAO
if [[ $EL_PATH_CODE == 1 ]]; then
	mkdir -p $EL_PATH
	chown elasticsearch.elasticsearch $EL_PATH
fi

mkdir -p $EL_PATH/backups
echo -e $TEMPLATE_ELASTICSEARCH_YML > /etc/elasticsearch/elasticsearch.yml
echo -e $TEMPLATE_ELASTICSEARCH_CRONTAB > /etc/crontab
sed -i 's/-Xms1g/-Xms2g/g' /etc/elasticsearch/jvm.options
sed -i 's/Xmx1g/Xmx2g/g' /etc/elasticsearch/jvm.options
cat /etc/crontab | cut -c2- > /etc/crontab.sc
mv /etc/crontab.sc /etc/crontab
sed -e 's/\\//g' /etc/crontab > /etc/crontab.sc
mv /etc/crontab.sc /etc/crontab
chmod 777 $EL_PATH/backups
cat /etc/elasticsearch/elasticsearch.yml | cut -c2- > /etc/elasticsearch/elastic.yml
mv /etc/elasticsearch/elastic.yml /etc/elasticsearch/elasticsearch.yml

service firewalld stop
systemctl disable firewalld
ntpdate -s ntp.infraero.gov.br
service elasticsearch start
service crond restart
}

instalar_snmp() {
yum install net-snmp net-snmp-libs net-snmp-utils -y
echo -e $TEMPLATE_SNMPD_CONF > /etc/snmp/snmpd.temp
cut -c2- /etc/snmp/snmpd.temp > /etc/snmp/snmpd.conf
rm -Rf /etc/snmp/snmpd.temp
systemctl enable snmpd
service snmpd restart
}

restaurar_backup_kibana() {
rsync -a -essh root@10.3.17.95:/log/backups/ $EL_PATH/backups/
chown -R elasticsearch.elasticsearch $EL_PATH/backups/
curl -X PUT $IP:9200/_snapshot/backup -H 'Content-Type: application/json' -d'
{
    "type": "fs",
    "settings": {
        "location": "/log/elasticsearch/backups",
        "compress": true
    }
}
'

curl -X POST $IP:9200/_snapshot/backup/kibana/_restore
curl -XPUT -H "Content-Type: application/json" $IP:9200/.kibana/_settings -d '{ "index.blocks.read_only" : false }'
}

inicio () {
echo -e "\n\n########################################\n\nDeseja confirmar a instalacao dos pacotes necessarios para o elasticsearch?\n1 - Sim\n2 - Nao\n\n########################################"
read -r CONFIRMA
if [[ $CONFIRMA == 1 ]];then
	instalacao
	configuracao
	instalar_snmp
	restaurar_backup_kibana
else
clear
echo -e "########################################Favor iniciar o script novamente para a instalacao do Elasticsearch.\n\n#######################################"
fi
}
inicio
