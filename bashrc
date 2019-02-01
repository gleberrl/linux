# /etc/bashrc
#####################################################
#Add this code in /etc/bashrc			    #
#####################################################

PROMPT_COMMAND=$(history -a)

typeset -r PROMPT_COMMAND

EDITOR=`echo "$command" | cut -d" " -f1`

TTY=`tty | cut -d"/" -f3-`
COUNTER=`w -i | wc -l`
I=3

while [[ $I -le $COUNTER ]]; do
	SRC_TTY[$I]=`w -i | awk '{ print $2}' | sed -n $I\p`
        if [[ $TTY == ${SRC_TTY[$I]} ]]; then
                SRC_IP=`w -i | awk '{ print $3}' | sed -n $I\p`
                break
        fi
        I=$(( $I + 1 ))
done

function log2syslog
{
   declare command
   command=$BASH_COMMAND

   EDITOR=`echo "$command" | cut -d" " -f1`

if [[ $EDITOR == "vim" || $EDITOR == "vi" || $EDITOR == "pico" || $EDITOR == "nano" ]]; then
        EDITOR_PATH=`echo "$command" | cut -d" " -f2-`
        OLD_FILE=`cat $EDITOR_PATH`
        PS=`ps -au | grep -w "$command"  | grep -v "grep" | awk '{ print $11" "$12 }'`
        COMMAND1="$command"
        SRC_IP1="$SRC_IP"
        TTY1="$TTY"
        USER1="$USER"
        PWD1="$PWD"

elif [[ $OLD_FILE != "" ]]; then
        PS=`ps -au | grep -w "$command"  | grep -v "grep" | awk '{ print $11" "$12 }'`
                if [[ $command != $PS ]]; then
                        NEW_FILE=`cat $EDITOR_PATH`
                        DIFF=`diff -u <(echo -e "$OLD_FILE") <(echo -e "$NEW_FILE")`
                        logger -p local1.notice -t bash -i -- $SRC_IP1 : $TTY1 : $USER1 : $PWD1 : $COMMAND1 : $DIFF
                        logger -p local1.notice -t bash -i -- $SRC_IP : $TTY : $USER : $PWD : $command : -
                        DIFF=""
                        OLD_FILE=""
                fi
else
   logger -p local1.notice -t bash -i -- $SRC_IP : $TTY : $USER : $PWD : $command : -
fi
}
trap log2syslog DEBUG
