#!/bin/bash 


# Function to print script usage
usage(){
    echo -e "Usage: $0 MAX_S MAX_R proto expType [rate[Mbps] max_rate[Mbps] delay[ms] iface[lo,eth0,...]"
    echo -e "MAX_S   = max number of slices (min is 2)"
    echo -e "MAX_R   = number of repetition of handshake per slice value"
    echo -e "proto   = protocol requested (ssl; spp)"
    echo -e "expType = {1=handshake ; 2=ping-like; 3=file_size(1K - 10MB)}"
    exit 0
}

# Kill eventual pending server processes 
killServer(){
for i in `ps aux | grep wserver | grep -v vi | grep -v grep | cut -f 2 -d " "`
do 
	kill -9 $i 
done
}

# Set of checks for correctness
[[ $# -lt 4 ]] && usage

# Parameters
S_MAX=$1        # max number of slices
R=$2            # number of repetitions per experiment
proto=$3        # protocol to be used
expType=$4      # experiment type
log="log_perf"  # performance log file
MAX=16          # hard coded max number of slices as per Kyle
fSizeMAX=10		# max file size is 10MB

# Small corection 
let "fSizeMAX = fSizeMAX*1024*1024"

# Cleaning network parameters, just in case 
./network.sh 2 

# Run few checks on input parameters
if [ $S_MAX -gt $MAX ] 
then 
	echo "Currently max number of slices is $MAX"
	exit 0
fi

if [ $S_MAX -lt 2 ] 
then 
	echo "Currently min number of slices is 2"
	exit 0
fi 

if [ $proto == "ssl" -o $proto == "spp" ] 
then 
	echo "Correct protocol requested ($proto)"
else	
	usage
fi 

# Optional parameters handling 
if [ $# -gt 4 ]
then 
	if [ $# -lt 8 ]
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

# Cleaning
if [ -f $log ]
then
	rm $log
fi

# Make sure server is not running
killServer

# Switch among user choices
case $expType in 

1)  # Test handshake duration 
	echo "Test handshake duration"
	opt=1

	# Start the server 
	echo "Starting the server"
	./wserver -c $proto -o $opt > log_server 2>&1 &

	# Give server small time to setup 
	sleep 1

	# Run S_MAX repetitions
	for((s=2; s<=S_MAX; s++))
	do
		# Run R handshake repetitions	
		echo "Testing $R handshakes with $s slices (1 slice is used for handshake)"
		for((i=1; i<R; i++))
		do
			./wclient -s $s -c $proto -o $opt >> $log 2>&1
		done
	done

	# Results 
	echo "#Handshake Analysis"
	echo "#Slices AvgDur StdDur"
	cat log_perf | grep Handshake_Dur | cut -f 2,4 -d " " | awk -f stdev.awk
	;;

3)	# Test download time as a function of file size for slice value range 
	echo "Test download time"
	opt=3
	
	# Start the server 
	echo "Starting the server"
	./wserver -c $proto -o $opt > log_server &
	
	# Give server small time to setup 
	sleep 1

	# Run S_MAX repetitions
	for((s=2; s<=S_MAX; s++))
	do
		# Run until fSize is bigger than fSizeMAX
		fSize=10
		let "fSize=10*1024" #(10KB)
		while [ $fSize -le $fSizeMAX ]
		do 
			# Run R handshake repetitions	
			echo "Test $R file retrievals with file size $fSize ($s slices)"
			for((i=1; i<R; i++))
			do
				./wclient -s $s -c $proto -o $opt -f $fSize >> $log
			done
	
			let "fSize = 2*fSize"
		done
	done
	;;

*)	
	;;
esac 


# Cleanup
if [ $# -eq 8 ]
then
	echo "Resetting network parameters (after experiment)"
	./network.sh 2
fi

# Kill the server
killServer

