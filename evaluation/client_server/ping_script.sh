#!/bin/bash 
# Measure delay in the following scenario
# Client ---> MBOX (Amazon-1) ---> Server (Amazon-2)

# Function to print script usage
usage(){
    echo -e "Usage: $0 command"
	echo -e "command = {ping, mtr}"
    exit 0
}

# check input is correct 
[[ $# -lt 1 ]] && usage

# Parameters
key="amazon.pem"                  # amazon key 
user="ubuntu"                     # amazon user 
timeSleep=5                       # time for server to setup
proxyFile="./proxyList_amazon"    # contains proxy information
log="rtt_results"                 # results file 
duration=30                       # measure for 1 minute
serverAdr="54.67.37.251"          # server address 
proxyAdr="54.76.148.166"          # middlebox address 
comm=$1                        # command to use


echo "[PING] Command chosen is $comm"

# cleaning 
rm rtt_report_*
rm pingSummary_*
rm pingSummary


# ping the server from the mbox
echo "[PING] MTR from mbox to the server ($serverAdr) (last $duration)"
if [ -f rtt_report_$serverAdr ] 
then 
	rm rtt_report_$serverAdr
fi
#command="mtr -c $duration --report $serverAdr > rtt_report_$serverAdr &"
command="./mtrTest.sh $serverAdr $duration &"
ssh -i $key $user@$proxyAdr "$command" &

# make sure on the server it will finish faster
sleep 1 


# Cleanup 
if [ -f pingSummary_$proxyAdr ] 
then 
	rm -v pingSummary_$proxyAdr 
fi

# ping or mtr the mbox from local machine 
if [ -f rtt_report_$proxyAdr ] 
then 
	rm rtt_report_$proxyAdr
fi

if [ $comm == "ping" ]
then 
	echo "[PING] PING from localhost to mbox ($proxyAdr) (last $duration)"
	ping -c $duration $proxyAdr > rtt_report_$proxyAdr
	cat rtt_report_$proxyAdr | grep avg | cut -f 2 -d "=" | cut -f 2 -d " " | awk 'BEGIN{FS="/"}{print $2 " " $NF}' > pingSummary_$proxyAdr
else
	echo "[PING] MTR from localhost to mbox ($proxyAdr) (last $duration)"
	mtr -c $duration --report $proxyAdr > rtt_report_$proxyAdr
	cat rtt_report_$proxyAdr | grep -v "HOST" | grep -v 2015 | awk '{if ($6>MAX){MAX=$6; stdev=$NF;}}END{print MAX " " stdev}' > pingSummary_$proxyAdr
fi


# collect results from mbox
scp -i $key $user@$proxyAdr:"./rtt_report_$serverAdr" ./
if [ -f pingSummary_$serverAdr ] 
then 
	rm -v pingSummary_$serverAdr
fi
cat rtt_report_$serverAdr | grep -v "HOST" | grep -v 2015 | awk '{if ($6>MAX){MAX=$6; stdev=$NF;}}END{print MAX " " stdev}' > pingSummary_$serverAdr

# compute time as the sum of the two and stdev as average
cat pingSummary_* | awk '{avg=avg+$1; stdev=stdev+$2;}END{print avg " " stdev/2}' > pingSummary

