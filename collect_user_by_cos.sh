#!/bin/sh

############################# collect_user_by_cos.sh #############################
# Version : 1.0                                                                  #
# Date : 19 Nov 2019                                                             #
# Author : Gleber Ribeiro Leite (gleberrl@yahoo.com.br)                          #
# Contributor(s):                                                                #
# Company: Bk Tecnologia da Informação                                           #
##################################################################################


date=`date +%Y-%m-%d`
dateh=`date '+%d-%m-%Y %H:%M:%S'`

cos=`/opt/zimbra/bin/zmprov gac -v | grep -e cn: -e zimbraId: | cut -d" " -f2`
i=1
while read -r cos_id[$i]
do
    i=$(( $i + 1 ))
done <<<"$cos"

i=1
j=1
while [[ ${cos_id[$i]} != "" ]]; do
    if [[ $(( $i % 2 )) -eq 0 ]]; then
        id_cos[$j]=${cos_id[$i]}
        j=$(( $j + 1 ))
    else
        name_cos[$j]=${cos_id[$i]}
    fi
    i=$(( $i + 1 ))
done
count_cos=$(( $j - 1 ))
echo -e "COS BY USER" > /tmp/collect.txt
echo -e "Estes dados sao gerados automaticamente." >> /tmp/collect.txt
echo -e "Data: $dateh" >> /tmp/collect.txt
echo -e " " >> /tmp/collect.txt
echo -e "CONTAS|COS" >> /tmp/collect.txt
i=1
cos[0]=0
while [[ $i -le $count_cos ]]; do
#    echo -e "====> COS: ${name_cos[$i]}" >> /tmp/collect.txt
    users=`/opt/zimbra/bin/zmprov -l gaa -v | grep -e uid: -e zimbraCOSId | grep -B1 ${id_cos[$i]} | grep uid: | grep -v granteeId: | awk '{print $2}'`
	j=1
	while read -r user[$j]
	do
		echo -e "USER: ${user[$j]}|COS: ${name_cos[$i]} " >> /tmp/collect.txt
		echo -e "${user[$j]}" >> /tmp/tmp_collect.txt
    		j=$(( $j + 1 ))
	done <<<"$users"
    i=$(( $i + 1 ))
    echo -e "=======================================================|================================" >> /tmp/collect.txt
    echo -e " " >> /tmp/collect.txt
done
echo -e " " >> /tmp/collect.txt
#echo -e "====> COS: default automatic" >> /tmp/collect.txt
i=1
j=1
tmp_user=`grep -v -e '^$' /tmp/tmp_collect.txt`
users=`/opt/zimbra/bin/zmprov -l gaa -v | grep -e uid: -e zimbraCOSId | grep -B1 "" | grep uid: | grep -v granteeId: | awk '{print $2}'`
while read -r user[$j]
do
	while read -r tmp[$i]
	do
		if [[ ${user[$j]} != ${tmp[$i]} ]];then
			echo -e "USER: ${user[$j]}|COS: default automatic " >> /tmp/collect.txt
		fi
                i=$(( $i + 1 ))
		break
	done <<<"$tmp_user"
	j=$(( $j + 1 ))
done <<<"$users"
rm -Rf /tmp/tmp_collect.txt
column /tmp/collect.txt -t -s "|" > /tmp/collect_user_by_cos.txt
rm -Rf /tmp/collect.txt
