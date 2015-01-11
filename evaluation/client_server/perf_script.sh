#!/bin/bash 


# Function to print script usage
usage(){
    echo -e "Usage: $0 S R"
    echo -e "S = max number of slices"
    echo -e "R = number of repetition of handshake per slice value"
    exit 0;
}

# Set of checks for correctness
[[ $# -lt 2 ]] && usage

# Parameters
S_MAX=$1        # max number of slices
R=$2            # number of repetitions per experiment
log="log_perf"  # performance log file


# cleaning
if [ -f $log ]
then
	rm $log
fi
# Make sure server is not running
killall wserver

# Start the server 
proto="spp"
opt=1
./wserver -c $proto -o $opt > log_server & 

# Give server small time to setup 
sleep 2

# Test the client
for((s=1; s<S_MAX; s++))
do
	for((i=1; i<R; i++))
	do
		./wclient -s $s -c $proto -o $opt >> $log
	done
done

# Results 
echo "#Handshake Analysis"
echo "#No. Slices Avg Dur Stdev Dur"
cat log_perf | grep Handshake_Dur | cut -f 2,4 -d " " | awk -f stdev.awk

