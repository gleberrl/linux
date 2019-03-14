#!/bin/sh

######CAPTURA DE DADOS
IP=`cat /etc/sysconfig/network-scripts/ifcfg-e* | grep IPADDR | cut -d"=" -f2`
IP_TEST=`echo $IP | grep \"`
IP_AD=`cat /etc/sysconfig/network-scripts/ifcfg-e* | grep DNS | grep -v IPV6 | cut -d"=" -f2`
IP_AD_TEST=`echo $IP_AD | grep \"`
IF_NAME=`cat /etc/sysconfig/network-scripts/ifcfg-e* | grep NAME | cut -d"=" -f2`

if [[ $IP_TEST == "" ]]; then
IP=`echo $IP`
else
IP=`echo $IP | cut -d"\"" -f2- | cut -d"\"" -f1`
fi

if [[ $IP_AD_TEST == "" ]]; then
IP_AD=`echo $IP_AD`
else
IP_AD=`echo $IP_AD | cut -d"\"" -f2- | cut -d"\"" -f1`
fi

echo -e "\n\n########################################\nDigite a sigla da localidade que o Kibana/Logstash sera instalado:\nExemplo: Manaus -> sbeg\n\nLocalidade:"
read -r LOCALIDADE
#echo -e "\n\nDigite o IP do Proxy:"
#read -r IP_PROXY
echo -e "\n\nDigite o IP do ElasticSearch (Banco de Dados):"
read -r IP_ELASTIC

#PROXY1=`echo -e "$IP_PROXY" | cut -d"." -f1`
#PROXY2=`echo -e "$IP_PROXY" | cut -d"." -f2`
#PROXY3=`echo -e "$IP_PROXY" | cut -d"." -f3`
#PROXY4=`echo -e "$IP_PROXY" | cut -d"." -f4`

TIMEZONES=`timedatectl list-timezones |grep America`
NUM_TIMEZONES=`timedatectl list-timezones |grep America | wc -l`
X=1
while [[ $X -le $NUM_TIMEZONES ]]; do
	TIMEZONE[$X]=`echo $X - $TIMEZONES | cut -d" " -f$X`
	echo -e "$X - ${TIMEZONE[$X]}"
	X=$(( $X + 1 ))
done
echo -e "\n\nDigite o Numero da respectiva timezone:\n"
read -r NUM_SELECTED_TIMEZONE
SELECTED_TIMEZONE=${TIMEZONE[$NUM_SELECTED_TIMEZONE]}

LOCALIDADE_M=`echo $LOCALIDADE | tr '[a-z]' '[A-Z]'`
LOCALIDADE_m=`echo $LOCALIDADE | tr '[A-Z]' '[a-z]'`
clear
echo -e "\n\n#########################################\n\nLocalidade de instalacao: $LOCALIDADE_M\nIP Logstash: $IP\nInterface maquina local: $IF_NAME\nIp do Proxy: $IP_PROXY\nIP Elasticsearch: $IP_ELASTIC\nIP AD: $IP_AD\nTimeZone Selecionado: $SELECTED_TIMEZONE\n\n########################################"

sleep 3
TEMPLATE_NGINX_CONF=$(cat <<TEMPLATE
user  nginx;
worker_processes  1;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    error_log   /var/log/nginx/error_debug.log debug;
        ldap_server AD1 {
                url "ldap://10.0.17.3:389/OU=SEDE,DC=infraero,DC=gov,DC=br?sAMAccountName?sub?(objectClass=person)";
                binddn "svc-sede-redes@infraero.gov.br";
                binddn_passwd infraero@wan;
                group_attribute member;
                group_attribute_is_dn on;
                satisfy any;
                require group "CN=SEDE_GB_ACESSO_KIBANA,OU=KIBANA,OU=Grupos,OU=SEDE,DC=infraero,DC=gov,DC=br";
        }

        ldap_server AD2 {
                url "ldap://$IP_AD:389/OU=Localidades,DC=infraero,DC=gov,DC=br?sAMAccountName?sub?(objectClass=person)";
                binddn "svc-sede-redes@infraero.gov.br";
                binddn_passwd infraero@wan;
                group_attribute member;
                group_attribute_is_dn on;
                satisfy any;
		require group "CN=$LOCALIDADE_M\_GB_ACESSO_KIBANA,OU=KIBANA,OU=Grupos,OU=SEDE,DC=infraero,DC=gov,DC=br";
        }
    auth_ldap_cache_enabled on;
    auth_ldap_cache_expiration_time 10000;
    auth_ldap_cache_size 10000;

    sendfile        on;
    keepalive_timeout  65;
    include /etc/nginx/conf.d/*.conf;
}
TEMPLATE
)
TEMPLATE_NGINX_KIBANA_CONF=$(cat <<TEMPLATE
server {
    listen 80;

    server_name $LOCALIDADE_m-kibana.noc.infranet.gov.br;
    return 301 https://\$server_name\$request_uri;
}

server {
        listen                  *:443;
        ssl on;
        ssl_certificate /etc/nginx/ssl/$LOCALIDADE_m-kibana.pem;
        ssl_certificate_key /etc/nginx/ssl/$LOCALIDADE_m-kibana.key;
        server_name           $IP;
        access_log            /var/log/nginx/kibana.access.log;
        error_log  /var/log/nginx/kibana.error.log;

        location / {
                auth_ldap "Closed content";
                auth_ldap_servers AD1 AD2;
                proxy_pass      http://$IP:5601;
                proxy_http_version 1.1;
                proxy_set_header Upgrade \$http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host \$host;
                proxy_cache_bypass \$http_upgrade;
        }
}
TEMPLATE
)

TEMPLATE_KIBANA_YML=$(cat <<TEMPLATE
# Kibana is served by a back end server. This setting specifies the port to use.
server.port: 5601

# Specifies the address to which the Kibana server will bind. IP addresses and host names are both valid values.
# The default is 'localhost', which usually means remote machines will not be able to connect.
# To allow connections from remote users, set this parameter to a non-loopback address.
server.host: "$IP"

# Enables you to specify a path to mount Kibana at if you are running behind a proxy. This only affects
# the URLs generated by Kibana, your proxy is expected to remove the basePath value before forwarding requests
# to Kibana. This setting cannot end in a slash.
#server.basePath: ""

# The maximum payload size in bytes for incoming server requests.
#server.maxPayloadBytes: 1048576

# The Kibana server's name.  This is used for display purposes.
#server.name: "your-hostname"

# The URL of the Elasticsearch instance to use for all your queries.
elasticsearch.url: "http://$IP_ELASTIC:9200"

# When this setting's value is true Kibana uses the hostname specified in the server.host
# setting. When the value of this setting is false, Kibana uses the hostname of the host
# that connects to this Kibana instance.
elasticsearch.preserveHost: true

# Kibana uses an index in Elasticsearch to store saved searches, visualizations and
# dashboards. Kibana creates a new index if the index doesn't already exist.
kibana.index: ".kibana"

# The default application to load.
#kibana.defaultAppId: "home"
kibana.defaultAppId: "dashboard/e3468920-548e-11e8-aa17-6badb59e458b"

# If your Elasticsearch is protected with basic authentication, these settings provide
# the username and password that the Kibana server uses to perform maintenance on the Kibana
# index at startup. Your Kibana users still need to authenticate with Elasticsearch, which
# is proxied through the Kibana server.
#elasticsearch.username: "user"
#elasticsearch.password: "pass"

# Enables SSL and paths to the PEM-format SSL certificate and SSL key files, respectively.
# These settings enable SSL for outgoing requests from the Kibana server to the browser.
#server.ssl.enabled: false

# If your Elasticsearch is protected with basic authentication, these settings provide
# the username and password that the Kibana server uses to perform maintenance on the Kibana
# index at startup. Your Kibana users still need to authenticate with Elasticsearch, which
# is proxied through the Kibana server.
#elasticsearch.username: "user"
#elasticsearch.password: "pass"

# Enables SSL and paths to the PEM-format SSL certificate and SSL key files, respectively.
# These settings enable SSL for outgoing requests from the Kibana server to the browser.
#server.ssl.enabled: false
#server.ssl.certificate: /path/to/your/server.crt
#server.ssl.key: /path/to/your/server.key

# Optional settings that provide the paths to the PEM-format SSL certificate and key files.
# These files validate that your Elasticsearch backend uses the same key files.
#elasticsearch.ssl.certificate: /path/to/your/client.crt
#elasticsearch.ssl.key: /path/to/your/client.key

# Optional setting that enables you to specify a path to the PEM file for the certificate
# authority for your Elasticsearch instance.
#elasticsearch.ssl.certificateAuthorities: [ "/path/to/your/CA.pem" ]

# To disregard the validity of SSL certificates, change this setting's value to 'none'.
#elasticsearch.ssl.verificationMode: full

# Time in milliseconds to wait for Elasticsearch to respond to pings. Defaults to the value of
# the elasticsearch.requestTimeout setting.
elasticsearch.pingTimeout: 3000

# Time in milliseconds to wait for responses from the back end or Elasticsearch. This value
# must be a positive integer.
elasticsearch.requestTimeout: 300000

# List of Kibana client-side headers to send to Elasticsearch. To send *no* client-side
# headers, set this value to [] (an empty list).
#elasticsearch.requestHeadersWhitelist: [ authorization ]

# Header names and values that are sent to Elasticsearch. Any custom headers cannot be overwritten
# by client-side headers, regardless of the elasticsearch.requestHeadersWhitelist configuration.
#elasticsearch.customHeaders: {}

# Time in milliseconds for Elasticsearch to wait for responses from shards. Set to 0 to disable.
elasticsearch.shardTimeout: 0
# Time in milliseconds to wait for Elasticsearch at Kibana startup before retrying.
#elasticsearch.startupTimeout: 5000

# Specifies the path where Kibana creates the process ID file.
#pid.file: /var/run/kibana.pid

# Enables you specify a file where Kibana stores log output.
#logging.dest: stdout

# Set the value of this setting to true to suppress all logging output.
#logging.silent: false

# Set the value of this setting to true to suppress all logging output other than error messages.
#logging.quiet: false

# Set the value of this setting to true to log all events, including system usage information
# and all requests.
#logging.verbose: false

# Set the interval in milliseconds to sample system and process performance
# metrics. Minimum is 100ms. Defaults to 5000.
#ops.interval: 5000

# The default locale. This locale can be used in certain circumstances to substitute any missing
# translations.
#i18n.defaultLocale: "en"
i18n.defaultLocale: "pt-br"
status.allowAnonymous: "true"
elasticsearch.requestHeadersWhitelist: "no"
TEMPLATE
)

TEMPLATE_LOGSTASH_00_CONF=$(cat <<TEMPLATE
input {
        syslog {
                port => 5544
                type => "proxy"
        }\n
}
TEMPLATE
)

TEMPLATE_LOGSTASH_20_CONF=$(cat <<TEMPLATE
filter{
        if "proxy" in [type]  {
                mutate {
                        add_tag => "proxy"
                }
        } else {
                 mutate {
                        add_tag => "others"
                }
        }
        if "_grokparsefailure" in [tags] or "_grokparsefailure_sysloginput" in [tags] or "_csvparsefailure" in [tags] or "_dateparsefailure" in [tags] or "beats_input_codec_plain_applied" in [tags] {
                mutate {
                        remove_tag => [ "_grokparsefailure", "_grokparsefailure_sysloginput", "_csvparsefailure","_dateparsefailure", "beats_input_codec_plain_applied"]
                }
        }
        if "others" in [tags] {
                drop {}
        }
}
TEMPLATE
)

TEMPLATE_LOGSTASH_40_CONF=$(cat <<TEMPLATE
filter  {
        if "proxy" in [type] {
                grok {
                        patterns_dir => "/etc/logstash/patterns"
                        match => [ "message", "%{SQUID}"]
                }

                date {
                        timezone => "$SELECTED_TIMEZONE"
                        match => [ "timeproxy" , "UNIX" ]
                }

                mutate {
                        remove_field => [ "message", "timeproxy", "content_type", "program", "method", "facility", "facility_label" ]
                }
                if "-" in [user] {
                        translate {
                                field => "src_ip"
                                destination => "user"
                                override => true
                                refresh_interval => "300"
                                dictionary_path =>  "/etc/logstash/dictionary/proxy_user.yaml"
                        }
                }
                if "\-" not in [user] {
                        translate {
                                field => "user"
                                destination => "group"
                                refresh_interval => "1200"
                                dictionary_path =>  "/etc/logstash/dictionary/proxy_group.yaml"
                        }
                }
        }
}
TEMPLATE
)

TEMPLATE_LOGSTASH_60_CONF=$(cat <<TEMPLATE
filter {
        if [type] == "proxy" {
				grok {
						patterns_dir => "/etc/logstash/patterns"
						match => [ "src_ip", "%{OCTETO:1octeto:int}\.%{OCTETO:2octeto:int}\.%{OCTETO:3octeto:int}\.%{OCTETO:4octeto:int}" ]
				}
		}
		if [2octeto] == 0 and [3octeto] <= 239 {
				mutate {
						add_field => {"local" => "SEDE_SCS"}
				}
		} else if [2octeto] == 1 {
				mutate {
						add_field => {"local" => "SBGL"}
				}
		} else if [2octeto] == 30 and ([3octeto] <= 127 or ([3octeto] >= 160 and [3octeto] <= 224)) {
				mutate {
						add_field => {"local" => "SBJR"}
				}
		} else if [2octeto] == 31 {
				mutate {
						add_field => {"local" => "SBRJ"}
				}
		} else if [2octeto] == 32 and ([3octeto] <= 127 or ([3octeto] >= 181 and [3octeto] <= 207)) {
				mutate {
						add_field => {"local" => "SBCP"}
				}
		} else if [2octeto] == 32 and ([3octeto] >= 128 and [3octeto] <= 159) {
				mutate {
						add_field => {"local" => "SBSF"}
				}
		} else if [2octeto] == 33 {
				mutate {
						add_field => {"local" => "SBME"}
				}
		} else if [2octeto] == 36 and ([3octeto] <= 127 or ([3octeto] >= 160 and [3octeto] <= 211)) {
				mutate {
						add_field => {"local" => "CSRJ"}
				}
		} else if [2octeto] == 36 and ([3octeto] >= 128 and [3octeto] <= 159) {
				mutate {
						add_field => {"local" => "SBOL"}
				}
		} else if [2octeto] == 2 {
				mutate {
						add_field => {"local" => "SBGR"}
				}
		} else if [2octeto] == 6 {
				mutate {
						add_field => {"local" => "SBBR"}
				}
		} else if [2octeto] == 40 and ([3octeto] <= 31 or [3octeto] == 176)  {
				mutate {
						add_field => {"local" => "SBMT"}
				}
		} else if [2octeto] == 40 and ([3octeto] >= 128 and [3octeto] <= 143) {
			mutate {
				add_field => {"local" => "TADN"}
			}
		} else if [2octeto] == 41 {
				mutate {
						add_field => {"local" => "SBSP"}
				}
		} else if [2octeto] == 42 {
				mutate {
						add_field => {"local" => "SBKP"}
				}
		} else if [2octeto] == 43 and [3octeto] <= 31  {
				mutate {
						add_field => {"local" => "TABU"}
				}
		} else if [2octeto] == 44 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBCG"}
				}
		} else if [2octeto] == 45 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBCR"}
				}
		} else if [2octeto] == 46 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBSJ"}
				}
		} else if [2octeto] == 47 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBPP"}
				}
		} else if [2octeto] == 48 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "TARP"}
				}
		} else if [2octeto] == 80 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBGO"}
				}
		} else if [2octeto] == 81 and ([3octeto] <= 31 or ([3octeto] >= 176 and [3octeto] <= 207)) {
				mutate {
						add_field => {"local" => "SBCY"}
				}
		} else if [2octeto] == 84 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "TAAT"}
				}
		} else if [2octeto] == 85 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBPJ"}
				}
		} else if [2octeto] == 86 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "TABW"}
				}
		} else if [2octeto] == 87 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBPN"}
				}
		} else if [2octeto] == 3 {
				mutate {
						add_field => {"local" => "SBEG"}
				}
		} else if [2octeto] == 50 and ([3octeto] <= 31 or ([3octeto] >= 181 and [3octeto] <= 207)) {
				mutate {
						add_field => {"local" => "SBRB"}
				}
		} else if [2octeto] == 50 and ([3octeto] >= 128 and [3octeto] <= 159) {
				mutate {
						add_field => {"local" => "SBVH"}
				}
		} else if [2octeto] == 51 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBTT"}
				}
		} else if [2octeto] == 51 and [3octeto] >= 128 {
				mutate {
						add_field => {"local" => "SBYA"}
				}
		} else if [2octeto] == 52 {
				mutate {
						add_field => {"local" => "SBBV"}
				}
		} else if [2octeto] == 53 {
				mutate {
						add_field => {"local" => "SBTF"}
				}
		} else if [2octeto] == 54 {
				mutate {
						add_field => {"local" => "SBPV"}
				}
		} else if [2octeto] == 55 {
				mutate {
						add_field => {"local" => "SBCZ"}
				}
		} else if [2octeto] == 56 {
				mutate {
						add_field => {"local" => "TAIC"}
				}
		} else if [2octeto] == 57 {
				mutate {
						add_field => {"local" => "TAMY"}
				}
		} else if [2octeto] == 58 {
				mutate {
						add_field => {"local" => "SBTK"}
				}
		} else if [2octeto] == 4 {
				mutate {
						add_field => {"local" => "SBPA"}
				}
		} else if [2octeto] == 60 and ([3octeto] <= 113 or ([3octeto] >= 176 and [3octeto] <= 225)) {
				mutate {
						add_field => {"local" => "SBCT"}
				}
		} else if [2octeto] == 60 and ([3octeto] >= 128 and [3octeto] <= 159) {
				mutate {
						add_field => {"local" => "SBCM"}
				}
		} else if [2octeto] == 61 {
				mutate {
						add_field => {"local" => "SBLO"}
				}
		} else if [2octeto] == 62 {
				mutate {
						add_field => {"local" => "SBJV"}
				}
		} else if [2octeto] == 63 {
				mutate {
						add_field => {"local" => "SBNF"}
				}
		} else if [2octeto] == 64 {
				mutate {
						add_field => {"local" => "SBFL"}
				}
		} else if [2octeto] == 65 {
				mutate {
						add_field => {"local" => "SBBI"}
				}
		} else if [2octeto] == 66 {
				mutate {
						add_field => {"local" => "SBFI"}
				}
		} else if [2octeto] == 67 {
				mutate {
						add_field => {"local" => "SBUG"}
				}
		} else if [2octeto] == 68 {
				mutate {
						add_field => {"local" => "SBPK"}
				}
		} else if [2octeto] == 69 {
				mutate {
						add_field => {"local" => "SBBG"}
				}
		} else if [2octeto] == 5 {
				mutate {
						add_field => {"local" => "SBRF"}
				}
		} else if [2octeto] == 70 and (([3octeto] >= 128 and [3octeto]<= 157) or ([3octeto] >= 224 and [3octeto] <= 239)) {
				mutate {
						add_field => {"local" => "SBPL"}
				}
		} else if [2octeto] == 70 and ([3octeto] <= 63 or ([3octeto] >= 176 and [3octeto] <= 223)) {
				mutate {
						add_field => {"local" => "SBSV"}
				}
		} else if [2octeto] == 71 and ([3octeto] <= 47 or ([3octeto] >= 176 and [3octeto] <= 208)) {
				mutate {
						add_field => {"local" => "SBFZ"}
				}
		} else if [2octeto] == 71 and ([3octeto] >= 128 and [3octeto] <= 147) {
				mutate {
						add_field => {"local" => "SBJU"}
				}
		} else if [2octeto] == 73 and ([3octeto] >= 128 and [3octeto] <= 143) {
				mutate {
						add_field => {"local" => "TAMS"}
				}
		} else if [2octeto] == 75 and ([3octeto] <= 47 or [3octeto] >= 224) {
				mutate {
						add_field => {"local" => "SBKG"}
				}
		} else if [2octeto] == 76 and ([3octeto] <= 47 or [3octeto] >= 156) {
				mutate {
						add_field => {"local" => "SBTE"}
				}
		} else if [2octeto] == 76 and ([3octeto] >= 128 and [3octeto] <= 157) {
				mutate {
						add_field => {"local" => "SBPB"}
                }
		} else if [2octeto] == 78 {
				mutate {
						add_field => {"local" => "SBJP"}
				}
		} else if [2octeto] == 7 {
				mutate {
						add_field => {"local" => "SBBE"}
				}
		} else if [2octeto] == 90 {
				mutate {
						add_field => {"local" => "SBSN"}
				}
		} else if [2octeto] == 91 and ([3octeto] >= 128 and [3octeto] <= 143) {
				mutate {
						add_field => {"local" => "TACI"}
				}
		} else if [2octeto] == 91 and ([3octeto] <= 36 or ([3octeto] >= 181 and [3octeto] <= 207)) {
				mutate {
						add_field => {"local" => "SBSL"}
				}
		} else if [2octeto] == 92 and [3octeto] <= 36 {
				mutate {
						add_field => {"local" => "SBMQ"}
				}
		} else if [2octeto] == 92 and [3octeto] >= 128 {
				mutate {
						add_field => {"local" => "TAEK"}
				}
		} else if [2octeto] == 93 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBHT"}
				}
		} else if [2octeto] == 93 and [3octeto] >= 128 {
				mutate {
						add_field => {"local" => "TAIH"}
				}
		} else if [2octeto] == 94 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBMA"}
				}
		} else if [2octeto] == 94 and [3octeto] >= 128 {
				mutate {
						add_field => {"local" => "TAMD"}
				}
		} else if [2octeto] == 95 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "TAAA"}
				}
		} else if [2octeto] == 95 and [3octeto] >= 128 {
				mutate {
						add_field => {"local" => "TATU"}
				}
		} else if [2octeto] == 96 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBCJ"}
				}
		} else if [2octeto] == 97 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBJC"}
				}
		} else if [2octeto] == 99 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBIZ"}
				}
		} else if [2octeto] == 30 and [3octeto] >= 128 {
				mutate {
						add_field => {"local" => "SBPR"}
				}
		} else if [2octeto] == 34 and ([3octeto] <= 79 or ([3octeto] >= 180 and [3octeto] <= 207)) {
				mutate {
						add_field => {"local" => "SBVT"}
				}
		} else if [2octeto] == 34 and ([3octeto] >= 128 and [3octeto] <= 143) {
				mutate {
						add_field => {"local" => "TAVO"}
				}
		} else if [2octeto] == 35 {
				mutate {
						add_field => {"local" => "SBBH"}
				}
		} else if [2octeto] == 37 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBMK"}
				}
		} else if [2octeto] == 38 {
				mutate {
						add_field => {"local" => "SBCF"}
				}
		} else if [2octeto] == 39 {
				mutate {
						add_field => {"local" => "CSBH"}
				}
		} else if [2octeto] == 49 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "TAPC"}
				}
		} else if [2octeto] == 82 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBUL"}
				}
		} else if [2octeto] == 83 {
				mutate {
						add_field => {"local" => "SBUR"}
				}
		} else if [2octeto] == 72 {
				mutate {
						add_field => {"local" => "SBMO"}
				}
		} else if [2octeto] == 74 and ([3octeto] <= 37 or [3octeto] >= 181) {
				mutate {
						add_field => {"local" => "SBAR"}
				}
		} else if [2octeto] == 74 and ([3octeto] >= 128 and [3octeto] <= 143) {
				mutate {
						add_field => {"local" => "TALP"}
				}
		} else if [2octeto] == 75 and [3octeto] >= 128 {
				mutate {
						add_field => {"local" => "SBQV"}
				}
		} else if [2octeto] == 77 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBIL"}
				}
		} else if [2octeto] == 77 and [3octeto] >= 128 {
				mutate {
						add_field => {"local" => "SBCV"}
				}
		} else if [2octeto] == 79 and [3octeto] <= 31 {
				mutate {
						add_field => {"local" => "SBUF"}
				}
		} else if [2octeto] == 8 {
				mutate {
						add_field => {"local" => "SEDE_AERO"}
				}
		}

		mutate {
			remove_field => [ "1octeto", "2octeto", "3octeto", "4octeto" ]
		}
		if "proxy" and "_grokparsefailure" in [tags] {
				drop {}
		}
		if ![local] {
				if [host] =~ "RTCSBR0(1|2)" or [host] == "RTGKSEDE01" {
						mutate {
								add_field => {"local" => "SEDE_SCS"}
						}
				} else if [host] =~ "RTCSBR1(1|2)" {
						mutate {
								add_field => {"local" => "SEDE_AERO"}
						}
				} else if [host] =~ "RT..VT0(1|2)" {
						mutate {
								add_field => {"local" => "SBVT"}
						}
				} else if [host] =~ "RT..VO0(1|2)" {
						mutate {
								add_field => {"local" => "TAVO"}
						}
				} else if [host] =~ "RT..UR0(1|2)" {
						mutate {
								add_field => {"local" => "SBUR"}
						}
				} else if [host] =~ "RT..UL0(1|2)" {
						mutate {
								add_field => {"local" => "SBUL"}
						}
				} else if [host] =~ "RT..VT0(1|2)" {
						mutate {
								add_field => {"local" => "SBVT"}
						}
				} else if [host] =~ "RT..UF0(1|2)" {
						mutate {
								add_field => {"local" => "SBUF"}
						}
				} else if [host] =~ "RT..TU0(1|2)" {
						mutate {
								add_field => {"local" => "TATU"}
						}
				} else if [host] =~ "RT..TK0(1|2)" {
						mutate {
								add_field => {"local" => "SBTK"}
						}
				} else if [host] =~ "RT..TF0(1|2)" {
						mutate {
								add_field => {"local" => "SBTF"}
						}
				} else if [host] =~ "RT..TE0(1|2)" {
						mutate {
								add_field => {"local" => "SBTE"}
						}
				} else if [host] =~ "RT..SN0(1|2)" {
						mutate {
								add_field => {"local" => "SBSN"}
						}
				} else if [host] =~ "RT..RP0(1|2)" {
						mutate {
								add_field => {"local" => "TARP"}
						}
				} else if [host] =~ "RT..RJ0(1|2)" {
						mutate {
								add_field => {"local" => "SBRJ"}
						}
				} else if [host] =~ "RT..PR0(1|2)" {
						mutate {
								add_field => {"local" => "SBPR"}
						}
				} else if [host] =~ "RT..PP0(1|2)" {
						mutate {
								add_field => {"local" => "SBPP"}
						}
				} else if [host] =~ "RT..PL0(1|2)" {
						mutate {
								add_field => {"local" => "SBPL"}
						}
				} else if [host] =~ "RT..PK0(1|2)" {
						mutate {
								add_field => {"local" => "SBPK"}
						}
				} else if [host] =~ "RT..PJ0(1|2)" {
						mutate {
								add_field => {"local" => "SBPJ"}
						}
				} else if [host] =~ "RT..PC0(1|2)" {
						mutate {
								add_field => {"local" => "TAPC"}
						}
				} else if [host] =~ "RT..PB0(1|2)" {
						mutate {
								add_field => {"local" => "SBPB"}
						}
				} else if [host] =~ "RT..NF0(1|2)" {
						mutate {
								add_field => {"local" => "SBNF"}
						}
				} else if [host] =~ "RT..MY0(1|2)" {
						mutate {
								add_field => {"local" => "TAMY"}
						}
				} else if [host] =~ "RT..MS0(1|2)" {
						mutate {
								add_field => {"local" => "TAMS"}
						}
				} else if [host] =~ "RT..MQ0(1|2)" {
						mutate {
								add_field => {"local" => "SBMQ"}
						}
				} else if [host] =~ "RT..MK0(1|2)" {
						mutate {
								add_field => {"local" => "SBMK"}
						}
				} else if [host] =~ "RT..ME0(1|2)" {
						mutate {
								add_field => {"local" => "SBME"}
						}
				} else if [host] =~ "RT..MD0(1|2)" {
						mutate {
								add_field => {"local" => "TAMD"}
						}
				} else if [host] =~ "RT..MA0(1|2)" {
						mutate {
								add_field => {"local" => "SBMA"}
						}
				} else if [host] =~ "RT..LP0(1|2)" {
						mutate {
								add_field => {"local" => "TALP"}
						}
				} else if [host] =~ "RT..LO0(1|2)" {
						mutate {
								add_field => {"local" => "SBLO"}
						}
				} else if [host] =~ "RT..KP0(1|2)" {
						mutate {
								add_field => {"local" => "SBKP"}
						}
				} else if [host] =~ "RT..KG0(1|2)" {
						mutate {
								add_field => {"local" => "SBKG"}
						}
				} else if [host] =~ "RT..JV0(1|2)" {
						mutate {
								add_field => {"local" => "SBJV"}
						}
				} else if [host] =~ "RT..JU0(1|2)" {
						mutate {
								add_field => {"local" => "SBJU"}
						}
				} else if [host] =~ "RT..JR0(1|2)" {
						mutate {
								add_field => {"local" => "SBJR"}
						}
				} else if [host] =~ "RT..JP0(1|2)" {
						mutate {
								add_field => {"local" => "SBJP"}
						}
				} else if [host] =~ "RT..JC0(1|2)" {
						mutate {
								add_field => {"local" => "SBJC"}
						}
				} else if [host] =~ "RT..IZ0(1|2)" {
						mutate {
								add_field => {"local" => "SBIZ"}
						}
				} else if [host] =~ "RT..IL0(1|2)" {
						mutate {
								add_field => {"local" => "SBIL"}
						}
				} else if [host] =~ "RT..IH0(1|2)" {
						mutate {
								add_field => {"local" => "TAIH"}
						}
				} else if [host] =~ "RT..IC0(1|2)" {
						mutate {
								add_field => {"local" => "TAIC"}
						}
				} else if [host] =~ "RT..HT0(1|2)" {
						mutate {
								add_field => {"local" => "SBHT"}
						}
				} else if [host] =~ "RT..GR0(1|2)" {
						mutate {
								add_field => {"local" => "SBGR"}
						}
				} else if [host] =~ "RT..GO0(1|2)" {
						mutate {
								add_field => {"local" => "SBGO"}
						}
				} else if [host] =~ "RT..GL0(1|2)" {
						mutate {
								add_field => {"local" => "SBGL"}
						}
				} else if [host] =~ "RT..EK0(1|2)" {
						mutate {
								add_field => {"local" => "TAEK"}
						}
				} else if [host] =~ "RT..DN0(1|2)" {
						mutate {
								add_field => {"local" => "TADN"}
						}
				} else if [host] =~ "RT..CZ0(1|2)" {
						mutate {
								add_field => {"local" => "SBCZ"}
						}
				} else if [host] =~ "RT..CP0(1|2)" {
						mutate {
								add_field => {"local" => "SBCP"}
						}
				} else if [host] =~ "RT..CM0(1|2)" {
						mutate {
								add_field => {"local" => "SBCM"}
						}
				} else if [host] =~ "RT..CJ0(1|2)" {
						mutate {
								add_field => {"local" => "SBCJ"}
						}
				} else if [host] =~ "RT..CI0(1|2)" {
						mutate {
								add_field => {"local" => "TACI"}
						}
				} else if [host] =~ "RT..BW0(1|2)" {
						mutate {
								add_field => {"local" => "TABW"}
						}
				} else if [host] =~ "RT..BU0(1|2)" {
						mutate {
								add_field => {"local" => "TABU"}
						}
				} else if [host] =~ "RT..BH0(1|2)" {
						mutate {
								add_field => {"local" => "SBBH"}
						}
				} else if [host] =~ "RT..BG0(1|2)" {
						mutate {
								add_field => {"local" => "SBBG"}
						}
				} else if [host] =~ "RT..AT0(1|2)" {
						mutate {
								add_field => {"local" => "TAAT"}
						}
				} else if [host] =~ "RT..AA0(1|2)" {
						mutate {
								add_field => {"local" => "TAAA"}
						}
				} else if [host] =~ "RT..UG0(1|2)" {
						mutate {
								add_field => {"local" => "SBUG"}
						}
				} else if [host] =~ "RT..TT0(1|2)" {
						mutate {
								add_field => {"local" => "SBTT"}
						}
				} else if [host] =~ "RT..SV0(1|2)" {
						mutate {
								add_field => {"local" => "SBSV"}
						}
				} else if [host] =~ "RT..SP0(1|2)" {
						mutate {
								add_field => {"local" => "SBSP"}
						}
				} else if [host] =~ "RT..SL0(1|2)" {
						mutate {
								add_field => {"local" => "SBSL"}
						}
				} else if [host] =~ "RT..SJ0(1|2)" {
						mutate {
								add_field => {"local" => "SBSJ"}
						}
				} else if [host] =~ "RT(SB|TA)RF0(1|2)" {
						mutate {
								add_field => {"local" => "SBRF"}
						}
				} else if [host] =~ "RT..RB0(1|2)" {
						mutate {
								add_field => {"local" => "SBRB"}
						}
				} else if [host] =~ "RT..PV0(1|2)" {
						mutate {
								add_field => {"local" => "SBPV"}
						}
				} else if [host] =~ "RT(SB|TA)PA0(1|2)" {
						mutate {
								add_field => {"local" => "SBPA"}
						}
				} else if [host] =~ "RT..OL0(1|2)" {
						mutate {
								add_field => {"local" => "SBOL"}
						}
				} else if [host] =~ "RT..MT0(1|2)" {
						mutate {
								add_field => {"local" => "SBMT"}
						}
				} else if [host] =~ "RT..MO0(1|2)" {
						mutate {
								add_field => {"local" => "SBMO"}
						}
				} else if [host] =~ "RT..FZ0(1|2)" {
						mutate {
								add_field => {"local" => "SBFZ"}
						}
				} else if [host] =~ "RT..FL0(1|2)" {
						mutate {
								add_field => {"local" => "SBFL"}
						}
				} else if [host] =~ "RT..FI0(1|2)" {
						mutate {
								add_field => {"local" => "SBFI"}
						}
				} else if [host] =~ "RT..EG0(1|2)" {
						mutate {
								add_field => {"local" => "SBEG"}
						}
				} else if [host] =~ "RT..CY0(1|2)" {
						mutate {
								add_field => {"local" => "SBCY"}
						}
				} else if [host] =~ "RT..CT0(1|2)" {
						mutate {
								add_field => {"local" => "SBCT"}
						}
				} else if [host] =~ "RT..CR0(1|2)" {
						mutate {
								add_field => {"local" => "SBCR"}
						}
				} else if [host] =~ "RT..CG0(1|2)" {
						mutate {
								add_field => {"local" => "SBCG"}
						}
				} else if [host] =~ "RT..CF0(1|2)" {
						mutate {
								add_field => {"local" => "SBCF"}
						}
				} else if [host] =~ "RT..BV0(1|2)" {
						mutate {
								add_field => {"local" => "SBBV"}
						}
				} else if [host] =~ "RT..BR0(1|2)" {
						mutate {
								add_field => {"local" => "SBBR"}
						}
				} else if [host] =~ "RT..BI0(1|2)" {
						mutate {
								add_field => {"local" => "SBBI"}
						}
				} else if [host] =~ "RT..BE0(1|2)" {
						mutate {
								add_field => {"local" => "SBBE"}
						}
				} else if [host] =~ "RT..AR0(1|2)" {
						mutate {
								add_field => {"local" => "SBAR"}
						}
				} else {
						mutate {
								add_field => {"local" => "Aplicacao"}
						}
				}
		}
}
TEMPLATE
)

TEMPLATE_LOGSTASH_99_CONF=$(cat <<TEMPLATE
output {
        if [type] == "wan" {
                elasticsearch {
                        index => "logstash-wan-$LOCALIDADE_m-%{+YYYY.MM}"
                        hosts => ["$IP_ELASTIC"]
                        }
        } else if [type] == "proxy" {
                elasticsearch {
                        index => "logstash-proxy-$LOCALIDADE_m-%{+YYYY.ww}"
                        hosts => ["$IP_ELASTIC"]
                }
                if [user] != "-" {
                        file {
                                path => "/tmp/proxy_user_general.yaml"
                                flush_interval => "60"
                                codec => line { format => "%{src_ip}: %{user}"}
                        }
                }
        } else {
                elasticsearch {
                        index => "logstash-others-$LOCALIDADE_m-%{+YYYY.MM}"
                        hosts => ["$IP_ELASTIC"]
                }
        }
}
TEMPLATE
)

TEMPLATE_GROK_SQUID=$(cat <<TEMPLATE
HOSTNAME1 \\\b(?:[0-9A-Za-z][0-9A-Za-z_-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\\\b)
IPORHOST1 (?:%{IP}|%{HOSTNAME1})

SQUID %{DATA:timeproxy}\s+%{NUMBER:tempo_resposta_ms:int} %{IPORHOST1:src_ip} (%{NOTSPACE:resposta_status}) %{NUMBER:bytes:int} %{WORD:method:string} (%{URIPROTO:http_proto}://)?%{IPORHOST1:dst_host}(?::%{POSINT:port})?(?:%{NOTSPACE:uri_param})? %{USERNAME:user} (%{NOTSPACE:proxy_response}) %{NOTSPACE:content_type:string}

OCTETO [0-9]{1,3}
MINEMONIC <[0-9]{1,3}>

TEMPLATE
)

TEMPLATE_GROK_ROUTER_CISCO=$(cat <<TEMPLATE
ROUTER_CISCO (<%{NUMBER:mnemonic_code}>%{INT:seq_number}: %{CISCOTIMESTAMP:log_date} %{DEL:timezone}: %%{CISCO_REASON:facility}-%{INT:severity}-%{CISCO_REASON:facility_mnemonic}: %{GREEDYDATA:message}|<%{NUMBER:mnemonic_code}>%{INT:seq_number}: %{CISCOTIMESTAMP:log_date} %{DEL:timezone}: %%{CISCO_REASON:facility}-%{CISCO_REASON:facility_sub}-%{INT:severity}-%{CISCO_REASON:facility_mnemonic}: %{GREEDYDATA:message})
CISCO_IOS (<%{NUMBER:mnemonic_code}>)?(%{INT:seq_number}: )?%{CISCOTIMESTAMP:log_date} %{DEL:timezone}: %%{CISCO_REASON:facility_name}-%{INT:severity}-%{CISCO_REASON:facility_mnemonic}: %{GREEDYDATA:message}
CISCO_IOS10 <%{NUMBER:mnemonic_code}>(%{INT:seq_number})?: (\.)?%{CISCOTIMESTAMP:log_date} %{DEL:timezone}: %%{DEL:facility_name}-%{INT:severity}-%{DEL:facility_mnemonic}: %{GREEDYDATA:message}
ROUTER_COMMAND %{DEL}:%{NOTSPACE:user}\s\s?%{DEL}:%{GREEDYDATA:command}
TEMPLATE
)

TEMPLATE_COLLECT_AD_SH=$(cat <<TEMPLATE
#!/bin/bash

############################### check_channels_dsp ###############################
# Version : 1.0                                                                  #
# Date : 31 May 2017                                                             #
# Gleber Ribeiro Leite (gleberrl@yahoo.com.br)                                   #
##################################################################################
#                                                                                #
#  COLLECT AD Groups/Users for dictionary logstash                               #
#                                                                                #
##################################################################################

####Group ProxySEDEAcessoPadrao
rm -Rf proxy_group_*
wbinfo --group-info=ProxySEDEAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySEDEAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySEDEAcessoPadrao.yaml
sed -i 's/,/: ProxySEDEAcessoPadrao\\\n/g' proxy_group_ProxySEDEAcessoPadrao.yaml

####Group ProxyAcessoBloqueado
wbinfo --group-info=ProxyAcessoBloqueado > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 33)}' > proxy_group_ProxyAcessoBloqueado.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAcessoBloqueado.yaml
sed -i 's/,/: ProxyAcessoBloqueado\\\n/g' proxy_group_ProxyAcessoBloqueado.yaml

####Group ProxyAcessoChats
wbinfo --group-info=ProxyAcessoChats > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 29)}' > proxy_group_ProxyAcessoChats.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAcessoChats.yaml
sed -i 's/,/: ProxyAcessoChats\\\n/g' proxy_group_ProxyAcessoChats.yaml

####Group ProxyAcessoDATI
wbinfo --group-info=ProxyAcessoDATI > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 28)}' > proxy_group_ProxyAcessoDATI.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAcessoDATI.yaml
sed -i 's/,/: ProxyAcessoDATI\\\n/g' proxy_group_ProxyAcessoDATI.yaml

####Group ProxyAcessoEspecial
wbinfo --group-info=ProxyAcessoEspecial > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 32)}' > proxy_group_ProxyAcessoEspecial.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAcessoEspecial.yaml
sed -i 's/,/: ProxyAcessoEspecial\\\n/g' proxy_group_ProxyAcessoEspecial.yaml

####Group ProxyAcessoEspecialEAD
wbinfo --group-info=ProxyAcessoEspecialEAD > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 35)}' > proxy_group_ProxyAcessoEspecialEAD.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAcessoEspecialEAD.yaml
sed -i 's/,/: ProxyAcessoEspecialEAD\\\n/g' proxy_group_ProxyAcessoEspecialEAD.yaml

####Group ProxyAcessoFW
wbinfo --group-info=ProxyAcessoFW > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 26)}' > proxy_group_ProxyAcessoFW.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAcessoFW.yaml
sed -i 's/,/: ProxyAcessoFW\\\n/g' proxy_group_ProxyAcessoFW.yaml

####Group ProxyAcessoGoogleEarth
wbinfo --group-info=ProxyAcessoGoogleEarth > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 35)}' > proxy_group_ProxyAcessoGoogleEarth.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAcessoGoogleEarth.yaml
sed -i 's/,/: ProxyAcessoGoogleEarth\\\n/g' proxy_group_ProxyAcessoGoogleEarth.yaml

####Group ProxyAcessoIntermediario
wbinfo --group-info=ProxyAcessoIntermediario > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 37)}' > proxy_group_ProxyAcessoIntermediario.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAcessoIntermediario.yaml
sed -i 's/,/: ProxyAcessoIntermediario\\\n/g' proxy_group_ProxyAcessoIntermediario.yaml

####Group ProxyAcessoNavegacaoAerea
wbinfo --group-info=ProxyAcessoNavegacaoAerea > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 38)}' > proxy_group_ProxyAcessoNavegacaoAerea.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAcessoNavegacaoAerea.yaml
sed -i 's/,/: ProxyAcessoNavegacaoAerea\\\n/g' proxy_group_ProxyAcessoNavegacaoAerea.yaml

####Group ProxyAcessoPadrao
wbinfo --group-info=ProxyAcessoPadrao > proxy_group_ProxyAcessoPadrao.yaml
cat proxy.yaml | awk '{print substr(\$0, 38)}' > proxy_group_ProxyAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAcessoPadrao.yaml
sed -i 's/,/: ProxyAcessoPadrao\\\n/g' proxy_group_ProxyAcessoPadrao.yaml

####Group ProxyAcessoTotal
wbinfo --group-info=ProxyAcessoTotal > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 29)}' > proxy_group_ProxyAcessoTotal.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAcessoTotal.yaml
sed -i 's/,/: ProxyAcessoTotal\\\n/g' proxy_group_ProxyAcessoTotal.yaml

####Group ProxyAcessoYoutube
#wbinfo --group-info=ProxyAcessoYoutube > proxy.yaml
#cat proxy.yaml | awk '{print substr(\$0, 33)}' > proxy_group_ProxyAcessoYoutube.yaml
#sed -i 's/\$/,/g' proxy_group_ProxyAcessoYoutube.yaml
#sed -i 's/,/: ProxyAcessoYoutube\\\n/g' proxy_group_ProxyAcessoYoutube.yaml

####Group ProxyAerosAcessoPadrao
wbinfo --group-info=ProxyAerosAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 35)}' > proxy_group_ProxyAerosAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxyAerosAcessoPadrao.yaml
sed -i 's/,/: ProxyAerosAcessoPadrao\\\n/g' proxy_group_ProxyAerosAcessoPadrao.yaml

####Group ProxySBBEAcessoPadrao
wbinfo --group-info=ProxySBBEAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBBEAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBBEAcessoPadrao.yaml
sed -i 's/,/: ProxySBBEAcessoPadrao\\\n/g' proxy_group_ProxySBBEAcessoPadrao.yaml

####Group ProxySBBRAcessoPadrao
#wbinfo --group-info=ProxySBBRAcessoPadrao > proxy.yaml
#cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBBRAcessoPadrao.yaml
#sed -i 's/\$/,/g' proxy_group_ProxySBBRAcessoPadrao.yaml
#sed -i 's/,/: ProxySBBRAcessoPadrao\\\n/g' proxy_group_ProxySBBRAcessoPadrao.yaml

####Group ProxySBCFAcessoPadrao
wbinfo --group-info=ProxySBCFAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBCFAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBCFAcessoPadrao.yaml
sed -i 's/,/: ProxySBCFAcessoPadrao\\\n/g' proxy_group_ProxySBCFAcessoPadrao.yaml

####Group ProxySBCGAcessoPadrao
wbinfo --group-info=ProxySBCGAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBCGAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBCGAcessoPadrao.yaml
sed -i 's/,/: ProxySBCGAcessoPadrao\\\n/g' proxy_group_ProxySBCGAcessoPadrao.yaml

####Group ProxySBCTAcessoPadrao
wbinfo --group-info=ProxySBCTAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBCTAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBCTAcessoPadrao.yaml
sed -i 's/,/: ProxySBCTAcessoPadrao\\\n/g' proxy_group_ProxySBCTAcessoPadrao.yaml

####Group ProxySBCYAcessoPadrao
wbinfo --group-info=ProxySBCYAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBCYAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBCYAcessoPadrao.yaml
sed -i 's/,/: ProxySBCYAcessoPadrao\\\n/g' proxy_group_ProxySBCYAcessoPadrao.yaml

####Group ProxySBEGAcessoPadrao
wbinfo --group-info=ProxySBEGAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBEGAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBEGAcessoPadrao.yaml
sed -i 's/,/: ProxySBEGAcessoPadrao\\\n/g' proxy_group_ProxySBEGAcessoPadrao.yaml

####Group ProxySBFIAcessoPadrao
wbinfo --group-info=ProxySBFIAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBFIAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBFIAcessoPadrao.yaml
sed -i 's/,/: ProxySBFIAcessoPadrao\\\n/g' proxy_group_ProxySBFIAcessoPadrao.yaml

####Group ProxySBFLAcessoPadrao
wbinfo --group-info=ProxySBFLAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBFLAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBFLAcessoPadrao.yaml
sed -i 's/,/: ProxySBFLAcessoPadrao\\\n/g' proxy_group_ProxySBFLAcessoPadrao.yaml

####Group ProxySBFZAcessoPadrao
wbinfo --group-info=ProxySBFZAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBFZAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBFZAcessoPadrao.yaml
sed -i 's/,/: ProxySBFZAcessoPadrao\\\n/g' proxy_group_ProxySBFZAcessoPadrao.yaml

####Group ProxySBGRAcessoPadrao
wbinfo --group-info=ProxySBGRAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBGRAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBGRAcessoPadrao.yaml
sed -i 's/,/: ProxySBGRAcessoPadrao\\\n/g' proxy_group_ProxySBGRAcessoPadrao.yaml

####Group ProxySBGLAcessoPadrao
wbinfo --group-info=ProxySBGLAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBGLAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBGLAcessoPadrao.yaml
sed -i 's/,/: ProxySBGLAcessoPadrao\\\n/g' proxy_group_ProxySBGLAcessoPadrao.yaml

####Group ProxySBJRAcessoPadrao
#wbinfo --group-info=ProxySBJRAcessoPadrao > proxy.yaml
#cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBJRAcessoPadrao.yaml
#sed -i 's/\$/,/g' proxy_group_ProxySBJRAcessoPadrao.yaml
#sed -i 's/,/: ProxySBJRAcessoPadrao\\\n/g' proxy_group_ProxySBJRAcessoPadrao.yaml

####Group ProxySBJVAcessoPadrao
wbinfo --group-info=ProxySBJVAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBJVAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBJVAcessoPadrao.yaml
sed -i 's/,/: ProxySBJVAcessoPadrao\\\n/g' proxy_group_ProxySBJVAcessoPadrao.yaml

####Group ProxySBKPAcessoPadrao
#wbinfo --group-info=ProxySBKPAcessoPadrao > proxy.yaml
#cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBKPAcessoPadrao.yaml
#sed -i 's/\$/,/g' proxy_group_ProxySBKPAcessoPadrao.yaml
#sed -i 's/,/: ProxySBKPAcessoPadrao\\\n/g' proxy_group_ProxySBKPAcessoPadrao.yaml

####Group ProxySBLOAcessoPadrao
wbinfo --group-info=ProxySBLOAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBLOAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBLOAcessoPadrao.yaml
sed -i 's/,/: ProxySBLOAcessoPadrao\\\n/g' proxy_group_ProxySBLOAcessoPadrao.yaml

####Group ProxySBMOAcessoPadrao
wbinfo --group-info=ProxySBMOAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBMOAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBMOAcessoPadrao.yaml
sed -i 's/,/: ProxySBMOAcessoPadrao\\\n/g' proxy_group_ProxySBMOAcessoPadrao.yaml

####Group ProxySBNFAcessoPadrao
wbinfo --group-info=ProxySBNFAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBNFAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBNFAcessoPadrao.yaml
sed -i 's/,/: ProxySBNFAcessoPadrao\\\n/g' proxy_group_ProxySBNFAcessoPadrao.yaml

####Group ProxySBNTAcessoPadrao
wbinfo --group-info=ProxySBNTAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBNTAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBNTAcessoPadrao.yaml
sed -i 's/,/: ProxySBNTAcessoPadrao\\\n/g' proxy_group_ProxySBNTAcessoPadrao.yaml

####Group ProxySBPAAcessoPadrao
wbinfo --group-info=ProxySBPAAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBPAAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBPAAcessoPadrao.yaml
sed -i 's/,/: ProxySBPAAcessoPadrao\\\n/g' proxy_group_ProxySBPAAcessoPadrao.yaml

####Group ProxySBPVAcessoPadrao
wbinfo --group-info=ProxySBPVAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBPVAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBPVAcessoPadrao.yaml
sed -i 's/,/: ProxySBPVAcessoPadrao\\\n/g' proxy_group_ProxySBPVAcessoPadrao.yaml

####Group ProxySBRBAcessoPadrao
wbinfo --group-info=ProxySBRBAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBRBAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBRBAcessoPadrao.yaml
sed -i 's/,/: ProxySBRBAcessoPadrao\\\n/g' proxy_group_ProxySBRBAcessoPadrao.yaml

####Group ProxySBRFAcessoPadrao
wbinfo --group-info=ProxySBRFAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBRFAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBRFAcessoPadrao.yaml
sed -i 's/,/: ProxySBRFAcessoPadrao\\\n/g' proxy_group_ProxySBRFAcessoPadrao.yaml

####Group ProxySBRJAcessoPadrao
wbinfo --group-info=ProxySBRJAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBRJAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBRJAcessoPadrao.yaml
sed -i 's/,/: ProxySBRJAcessoPadrao\\\n/g' proxy_group_ProxySBRJAcessoPadrao.yaml

####Group ProxySBSPAcessoPadrao
wbinfo --group-info=ProxySBSPAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBSPAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBSPAcessoPadrao.yaml
sed -i 's/,/: ProxySBSPAcessoPadrao\\\n/g' proxy_group_ProxySBSPAcessoPadrao.yaml

####Group ProxySBVTAcessoPadrao
wbinfo --group-info=ProxySBVTAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBVTAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBVTAcessoPadrao.yaml
sed -i 's/,/: ProxySBVTAcessoPadrao\\\n/g' proxy_group_ProxySBVTAcessoPadrao.yaml

####Group ProxySRRJAcessoPadrao
wbinfo --group-info=ProxySRRJAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySRRJAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySRRJAcessoPadrao.yaml
sed -i 's/,/: ProxySRRJAcessoPadrao\\\n/g' proxy_group_ProxySRRJAcessoPadrao.yaml

####Group ProxySRSEAcessoPadrao
wbinfo --group-info=ProxySRSEAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySRSEAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySRSEAcessoPadrao.yaml
sed -i 's/,/: ProxySRSEAcessoPadrao\\\n/g' proxy_group_ProxySRSEAcessoPadrao.yaml

####Group ProxySRSVAcessoPadrao
wbinfo --group-info=ProxySRSVAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySRSVAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySRSVAcessoPadrao.yaml
sed -i 's/,/: ProxySRSVAcessoPadrao\\\n/g' proxy_group_ProxySRSVAcessoPadrao.yaml

####Group ProxySBMTAcessoPadrao
wbinfo --group-info=ProxySBMTAcessoPadrao > proxy.yaml
cat proxy.yaml | awk '{print substr(\$0, 34)}' > proxy_group_ProxySBMTAcessoPadrao.yaml
sed -i 's/\$/,/g' proxy_group_ProxySBMTAcessoPadrao.yaml
sed -i 's/,/: ProxySBMTAcessoPadrao\\\n/g' proxy_group_ProxySBMTAcessoPadrao.yaml

rm -Rf proxy.yaml
#cat proxy_group_Proxy* > proxy_group.yaml
date > proxy_group.yaml
sed -i 's/^/#/g' proxy_group.yaml
cat proxy_group_ProxySBBEAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBCFAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBCGAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBCTAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBCYAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBEGAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBFIAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBFLAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBFZAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBGLAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBGRAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBJVAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBLOAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBMOAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBNFAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBNTAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBPAAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBPVAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBRBAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBRFAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBRJAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBSPAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBVTAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySRRJAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySRSEAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySRSVAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySBMTAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxyAerosAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxySEDEAcessoPadrao.yaml >> proxy_group.yaml
cat proxy_group_ProxyAcessoBloqueado.yaml >> proxy_group.yaml
cat proxy_group_ProxyAcessoChats.yaml >> proxy_group.yaml
cat proxy_group_ProxyAcessoGoogleEarth.yaml >> proxy_group.yaml
cat proxy_group_ProxyAcessoNavegacaoAerea.yaml >> proxy_group.yaml
cat proxy_group_ProxyAcessoIntermediario.yaml >> proxy_group.yaml
cat proxy_group_ProxyAcessoTotal.yaml >> proxy_group.yaml
cat proxy_group_ProxyAcessoFW.yaml >> proxy_group.yaml
cat proxy_group_ProxyAcessoEspecial.yaml >> proxy_group.yaml
cat proxy_group_ProxyAcessoEspecialEAD.yaml >> proxy_group.yaml

rm -Rf proxy_group_Proxy*

TEMPLATE
)

TEMPLATE_COLLECT_USER=$(cat <<TEMPLATE
#!/bin/bash\n\n

################################# COLLECT_user.sh ################################
# Version : 1.0                                                                  #
# Date : 31 May 2017                                                             #
# Gleber Ribeiro Leite (gleberrl@yahoo.com.br)                                   #
##################################################################################
#                                                                                #
#  COLLECT AD Groups/Users for dictionary logstash                               #
#                                                                                #
##################################################################################
cat /etc/logstash/dictionary/proxy_user.yaml > /tmp/proxy_user_resum.yaml
sed -i '1d' /tmp/proxy_user_resum.yaml
awk -F"#" '{ arr[\$1]=\$0;} END{ for(v in arr) print arr[v]}'  /tmp/proxy_user_general.yaml >> /tmp/proxy_user_resum.yaml
rm -Rf /tmp/proxy_user_general.yaml
date > /etc/logstash/dictionary/proxy_user.yaml
sed -i 's/^/#/g' /etc/logstash/dictionary/proxy_user.yaml
echo "10.0.27.141: svc-sede-icinga" >> /etc/logstash/dictionary/proxy_user.yaml
awk -F"#" '{ arr[\$1]=\$0;} END{ for(v in arr) print arr[v]}'  /tmp/proxy_user_resum.yaml >> /etc/logstash/dictionary/proxy_user.yaml
TEMPLATE
)

TEMPLATE_LOGSTASH_CRONTAB=$(cat <<TEMPLATE
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed
0 0 * * * root service ntpd restart
0 * * * * root cd /etc/logstash/dictionary && ./collect_AD.sh
*/5 * * * * root /etc/logstash/dictionary/collect_user.sh
5 0 * * * root echo  > /etc/logstash/dictionary/proxy_user.yaml
5 0 * * * root echo  > /tmp/proxy_user_general.yaml
5 0 * * * root echo  > /tmp/proxy_user_resum.yaml
TEMPLATE
)

TEMPLATE_PROXY_USER_YAML=$(cat <<TEMPLATE
10.0.27.141: svc-sede-icinga
TEMPLATE
)

TEMPLATE_PROXY_GROUP_YAML=$(cat <<TEMPLATE
svc-sede-icinga: ProxyAcessoTotal
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
yum update -y
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
echo -e "[logstash-6.x]\nname=Elastic repository for 6.x packages\nbaseurl=https://artifacts.elastic.co/packages/6.x/yum\ngpgcheck=1\ngpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch\nenabled=1\nautorefresh=1\ntype=rpm-md" > /etc/yum.repos.d/logstash.repo
echo -e "[kibana-6.x]\nname=Kibana repository for 6.x packages\nbaseurl=https://artifacts.elastic.co/packages/6.x/yum\ngpgcheck=1\ngpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch\nenabled=1\nautorefresh=1\ntype=rpm-md" > /etc/yum.repos.d/kibana.repo

yum install -y java-1.8.0-openjdk.x86_64 kibana logstash vim ntpdate screen less unzip bzip2 multitail htop nmap tcpdump rsync traceroute iptraf iperf openssl-devel pcre-devel openldap-devel nginx wget lsof net-tools
yum groupinstall -y "Development Tools"
systemctl enable logstash
systemctl enable kibana
service firewalld stop
systemctl disable firewalld
mkdir /tmp/build
wget http://nginx.org/download/nginx-1.9.9.tar.gz -P /tmp/build
wget https://github.com/kvspb/nginx-auth-ldap/archive/master.zip -P /tmp/build
tar -zxf /tmp/build/nginx-1.9.9.tar.gz -C /tmp/build/
unzip /tmp/build/master.zip -d /tmp/build/
cd /tmp/build/nginx-1.9.9/ && ./configure --user=nginx --group=nginx --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --with-http_gzip_static_module --with-http_stub_status_module --with-http_ssl_module --with-pcre --with-file-aio --with-http_realip_module --add-module=/tmp/build/nginx-auth-ldap-master --with-ipv6 --with-debug
cd /tmp/build/nginx-1.9.9/ && make
cd /tmp/build/nginx-1.9.9/ && make install
systemctl enable nginx
rm -Rf /tmp/build
mkdir -p /etc/nginx/ssl
mkdir -p /etc/logstash/patterns
mkdir -p /etc/logstash/dictionary
}

configuracao_logstash () {
sed -i 's/-Xms256m/-Xms2g/g' /etc/logstash/jvm.options
sed -i 's/-Xmx1g/-Xmx2g/g' /etc/logstash/jvm.options

echo -e "$TEMPLATE_LOGSTASH_00_CONF" > /etc/logstash/conf.d/00-input_default.conf
echo -e "$TEMPLATE_LOGSTASH_20_CONF" > /etc/logstash/conf.d/20-filter_tags.conf
echo -e "$TEMPLATE_LOGSTASH_40_CONF" > /etc/logstash/conf.d/40-filter_grok_proxy.conf
echo -e "$TEMPLATE_LOGSTASH_60_CONF" > /etc/logstash/conf.d/60-filter_proxy_localidade.conf
echo -e "$TEMPLATE_LOGSTASH_99_CONF" > /etc/logstash/conf.d/99-output_default.conf

echo -e "$TEMPLATE_GROK_SQUID" > /etc/logstash/patterns/grok_squid
echo -e "$TEMPLATE_GROK_ROUTER_CISCO" > /etc/logstash/patterns/grok_router_cisco

echo -e "$TEMPLATE_COLLECT_AD_SH" > /etc/logstash/dictionary/collect_AD.sh
echo -e "$TEMPLATE_COLLECT_USER" > /etc/logstash/dictionary/collect_user.sh
echo -e "$TEMPLATE_PROXY_USER_YAML" > /etc/logstash/dictionary/proxy_user.yaml
echo -e "$TEMPLATE_PROXY_GROUP_YAML" > /etc/logstash/dictionary/proxy_group.yaml

echo -e "$TEMPLATE_LOGSTASH_CRONTAB" > /etc/crontab

chmod 777 /etc/logstash/dictionary/*
chmod 777 /tmp/proxy_user_*
/usr/share/logstash/bin/logstash-plugin install logstash-filter-translate
}

gerar_certificado () {
openssl req -newkey rsa:2048 -nodes -keyout /etc/nginx/ssl/$LOCALIDADE_m-kibana.key -out /etc/nginx/ssl/$LOCALIDADE_m-kibana.csr -outform pem -subj "/C=BR/ST=DF/L=Brasilia/O=Infraero/OU=TIIN-3/CN=$LOCALIDADE_m-kibana.noc.infranet.gov.br"
}

configuracao_nginx () {
echo -e "$TEMPLATE_NGINX_CONF" > /etc/nginx/nginx.conf
echo -e "$TEMPLATE_NGINX_KIBANA_CONF" > /etc/nginx/conf.d/kibana.conf

}

configuracao_kibana () {
echo -e "$TEMPLATE_KIBANA_YML" > /etc/kibana/kibana.yml

chmod +x /etc/rc.local
echo "/sbin/iptables -A INPUT -i $IF_NAME -p tcp --destination-port 5601 -j DROP" >> /etc/rc.local
/sbin/iptables -A INPUT -i $IF_NAME -p tcp --destination-port 5601 -j DROP

}

instalar_snmp() {
yum install net-snmp net-snmp-libs net-snmp-utils -y
echo -e $TEMPLATE_SNMPD_CONF > /etc/snmp/snmpd.temp
cut -c2- /etc/snmp/snmpd.temp > /etc/snmp/snmpd.conf
rm -Rf /etc/snmp/snmpd.temp
systemctl enable snmpd
service snmpd restart
}

inicio () {
echo -e "\n\n########################################\n\nDeseja confirmar a instalacao dos pacotes necessarios para o Kibana/Logstash?\n1 - Sim\n2 - Nao\n\n########################################"
read -r CONFIRMA
if [[ $CONFIRMA == 1 ]];then
	instalacao
	configuracao_nginx
	configuracao_kibana
	configuracao_logstash
	gerar_certificado
	instalar_snmp
	cat /etc/nginx/ssl/$LOCALIDADE_m-kibana.csr
	service logstash restart
	service kibana restart
	service nginx restart
else
clear
echo -e "########################################Favor iniciar o script novamente para a instalacao do Kibana/Logstash.\n\n#######################################"
fi
}
inicio
