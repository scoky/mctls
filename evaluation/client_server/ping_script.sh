#!/bin/bash 
# Measure delay in the following scenario
# Client ---> MBOX (Amazon-1) ---> Server (Amazon-2)

# Function to print script usage
usage(){
    echo -e "Usage: $0 MAX_S MAX_R proto expType remote [rate[Mbps] max_rate[Mbps] delay[ms] iface[lo,eth0,...]"
    exit 0
}

# Parameters
key="amazon.pem"                  # amazon key 
user="ubuntu"                     # amazon user 
timeSleep=5                       # time for server to setup
proxyFile="./proxyList_amazon"    # contains proxy information
log="rtt_results"                 # results file 
duration=30                       # measure for 1 minute
serverAdr="54.67.37.251"          # server address 
proxyAdr="54.76.148.166"          # middlebox address 

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

# ping the mbox from local machine 
if [ -f rtt_report_$proxyAdr ] 
then 
	rm rtt_report_$proxyAdr
fi
echo "[PING] MTR from localhost to mbox ($proxyAdr) (last $duration)"
mtr -c $duration --report $proxyAdr > rtt_report_$proxyAdr
if [ -f pingSummary_$proxyAdr ] 
then 
	rm -v pingSummary_$proxyAdr 
fi
cat rtt_report_$proxyAdr | grep -v "HOST" | grep -v 2015 | awk '{if ($6>MAX){MAX=$6; stdev=$NF;}}END{print MAX " " stdev}' > pingSummary_$proxyAdr

# collect results from mbox
scp -i $key $user@$proxyAdr:"./rtt_report_$serverAdr" ./
if [ -f pingSummary_$serverAdr ] 
then 
	rm -v pingSummary_$serverAdr
fi
cat rtt_report_$serverAdr | grep -v "HOST" | grep -v 2015 | awk '{if ($6>MAX){MAX=$6; stdev=$NF;}}END{print MAX " " stdev}' > pingSummary_$serverAdr

# compute time as the sum of the two and stdev as average
cat pingSummary_* | awk '{avg=avg+$1; stdev=stdev+$2;}END{print avg " " stdev/2}' > pingSummary

