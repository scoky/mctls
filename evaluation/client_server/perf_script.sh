#!/bin/bash 


# Function to print script usage
usage(){
    echo -e "Usage: $0 MAX_S MAX_R [rate[Mbps] max_rate[Mbps] delay[ms]]"
    echo -e "MAX_S = max number of slices"
    echo -e "MAX_R = number of repetition of handshake per slice value"
    exit 0
}

# Set of checks for correctness
[[ $# -lt 2 ]] && usage

# Parameters
S_MAX=$1        # max number of slices
R=$2            # number of repetitions per experiment
proto=$3        # protocol to be used
log="log_perf"  # performance log file
MAX=16          # hard coded max number of slices as per Kyle

# Cleaning network parameters, just in case 
./network.sh 2 

# Check 
if [ $S_MAX -gt $MAX ] 
then 
	echo "Currently max number of slices is $MAX"
	exit 0
fi 

# Optional parameters handling 
if [ $# -gt 3 ]
then 
	if [ $# -lt 6 ]
	then 
		echo "Running with no network config. For net conf. you need 4 optional parameters: [rate[Mbps] max_rate[Mbps] delay[ms] iface"
	else
		rate=$4
		maxRate=$5
		delay=$6
		iface=$7
		echo "Setting up local network parameters - Rate=" $rate "Mbps MaxRate=" $maxRate " Delay=" $delay "Interface=$iface"
		./network.sh 1 $rate $maxRate $delay $iface
	fi
else
	echo "Running with no network config. For net conf. you need 4 optional parameters: [rate[Mbps] max_rate[Mbps] delay[ms] iface"
fi

# cleaning
if [ -f $log ]
then
	rm $log
fi
# Make sure server is not running
killall wserver

# Start the server 
opt=1
./wserver -c $proto -o $opt > log_server & 

# Give server small time to setup 
sleep 2

# Test the client
for((s=1; s<=S_MAX; s++))
do
	echo "$R repetitions with $s slices (1 slice is used for handshake)"
	for((i=1; i<R; i++))
	do
		./wclient -s $s -c $proto -o $opt >> $log
	done
done

# Results 
echo "#Handshake Analysis"
echo "#No. Slices Avg Dur Stdev Dur"
cat log_perf | grep Handshake_Dur | cut -f 2,4 -d " " | awk -f stdev.awk

# Cleanup
if [ $# -eq 6 ]
then
	echo "Resetting network parameters"
	./network.sh 2
fi
