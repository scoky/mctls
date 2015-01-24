#!/bin/bash 

# Function to print script usage
usage(){
    echo -e "Usage: $0 opt s proto remote [rate[Mbps] max_rate[Mbps] delay[ms] iface[lo,eth0,...]"
    echo -e "opt = {(1) (2) (3) (4) (5) (6) (7) (8)}"
	echo -e "\t(1) Test handshake "
	echo -e "\t(2) Test time to first byte"
	echo -e "\t(3) Test N proxies (set N in the script)"
	echo -e "\t(4) Test file download (1MB)"
	echo -e "\t(5) Test number of connection per second"
    echo -e "s      = number of slices"
    echo -e "proto  = protocol to be used"
    echo -e "remote = {(0) local experiments (1) Amazon experiments}"
    echo -e "[optional parameters require <<tc>>, ok on Amazon"
    exit 0
}

# Get common functions with script <<perf_script.sh>>
source function.sh

# Check input for minimum number of parameteres requestes
[[ $# -lt 4 ]] && usage

# Parameters
opt=$1                     # test option 
s=$2                       # number of slices
proto=$3                   # protocol to be used
REMOTE=$4                  # 1=remote ; 0=local 
log="log_client"           # performance log file
proxyFile="./proxyList"    # contains proxy information 
key="amazon.pem"           # amazon key 
user="ubuntu"              # amazon user 
remoteFolder="/home/$user/secure_proxy_protocol/evaluation/client_server" # remote folder
timeSleep=5                # time for server to setup
strategy="uni"             # splitting strategy at the server 

#Logging 
echo "[PERF] Sumary of user input -- Slices=$s ; Protocol=$proto ; Test type=$opt"


# Cleaning network parameters, just in case
if [ $# -eq 8 ]
then  
	echo "[PERF] Cleaning network parameters (just in case)"
	./network.sh 2 
fi

# More cleaning
for i in `ls | grep log_mbox`
do 
	rm -v $i 
done 

# Restore original proxy configuration
if [ $REMOTE -eq 0 ] 
then 
	cp $proxyFile"_original" $proxyFile 
	echo "[PERF] Using proxy configuration as from file "$proxyFile"_original"
else
	cp $proxyFile"_amazon" $proxyFile 
	echo "[PERF] Using proxy configuration as from file "$proxyFile"_amazon"
fi

# Optional parameters handling 
if [ $# -gt 4 ]
then 
	if [ $# -lt 8 ]
	then 
		echo "[PERF] Running with no network config. For net conf. you need 4 optional parameters: [rate[Mbps] max_rate[Mbps] delay[ms] iface"
	else
		rate=$5
		maxRate=$6
		delay=$7
		iface=$8
		echo "[PERF] Setting up local network parameters - Rate=" $rate"Mbps MaxRate="$maxRate"Mbps Delay="$delay"ms Interface=$iface"
		./network.sh 1 $rate $maxRate $delay $iface
		echo "[PERF] Veryfying network configuration"
		if [ $iface == "lo" ] 
		then 
			ping -c 3 localhost
		fi
	fi
else
	echo "[PERF] Running with no network config. For net conf. you need 4 optional parameters: [rate[Mbps] max_rate[Mbps] delay[ms] iface"
fi

# Cleaning
if [ -f $log ]
then
	rm $log
fi

# Read mboxes (and server) address from config file
if [ $opt -ne 3 ] 
then
	readMboxes
fi

# Make sure server is not running
killServer

# Switch among user choices
case $opt in 

	1)  # Test handshake 
		echo "[TEST] Test handshake"
		opt=1

		# Start the server 
		start_server
		
		# Start middleboxes 
		organizeMBOXES

		# Start the client 
		echo "[TEST] Client started" 
		echo "./wclient -s $s -r 1 -w 1 -c $proto -o $opt >> $log 2>&1"
		./wclient -s $s -r 1 -w 1 -c $proto -o $opt >> $log 2>&1
		;;

	2)  # Test time to first byte 
		echo "[TEST] Test time to first byte"
		opt=2

		# Start the server 
		start_server

		# Start middleboxes 
		organizeMBOXES
		
		# Start the client 
		echo "[TEST] Client started" 
		echo "./wclient -s $s -r 1 -w 1 -c $proto -o $opt >> $log 2>&1"
		./wclient -s $s -r 1 -w 1 -c $proto -o $opt >> $log 2>&1
		;;
	
	
	3)  # Test N  proxies 
		N=16
		echo "[TEST] Test $N proxies"
		if [ $REMOTE -eq 1 ] 
		then 
			echo "[TEST] ERROR - Only two Amazon machines available, i.e., cannot test N proxies (N=4). Run locally!"
			exit 0 
		fi
		opt=2
		
		# Start the server 
		start_server
		
		# Update proxy file 
		proxyFileUpdate 

		# Read proxy from (updated) file
		readMboxes

		# Start middleboxes 
		organizeMBOXES
			
		# Starting client 
		echo "[TEST] Client started" 
		echo "./wclient -s $s -r 1 -w 1 -c $proto -o $opt >> $log 2>&1"
		./wclient -s $s -r 1 -w 1 -c $proto -o $opt >> $log 2>&1
		
		# Restore original proxy file (user for other experiments)
		cp $proxyFile"_original" $proxyFile
		;;



	4)	# Test file download
		echo "[TEST] Test file download (1MB)"
		opt=3
	
		# Start the server 
		start_server

		# Start middleboxes 
		organizeMBOXES

		# Run until fSize is bigger than fSizeMAX
		fSize=1024
		let "fSize=fSize*1024"
		echo "./wclient -s $s -c $proto -o $opt -f $fSize -r 1 -w 1 >> $log 2>/dev/null"
		./wclient -s $s -c $proto -o $opt -f $fSize -r 1 -w 1 >> $log 2>/dev/null
		;;	

	5)  # Test number of connection per second  
		echo "[TEST] Test number of connection per second (last 10 seconds)"
		opt=1
		testDur=10       
		pathOpenSSL="/usr/local/ssl/bin/openssl"
		cipher="DHE-RSA-AES128-SHA256"

		# Start the server 
		start_server
		
		# Start middleboxes 
		organizeMBOXES
		
		# Get next hop address 
		nextHop=`cat $proxyFile | awk '{if(count==1)print $0; count+=1}'`

		# Start the client 
		echo "[TEST] Start s_time utility"
		echo "$pathOpenSSL s_time -connect $nextHop -new -time $testDur -proto $proto -slice $s -read 1 -write 1 -cipher $cipher >> $log 2>&1"
		$pathOpenSSL s_time -connect $nextHop -new -time $testDur -proto $proto -slice $s -read 1 -write 1 -cipher $cipher >> $log 2>&1
		;; 

	*)	
		;;
esac 

# Cleanup
if [ $# -eq 8 ]
then
	echo "[TEST] Resetting network parameters (after experiment)"
	./network.sh 2
fi

# Kill the server
killServer

# Kill mboxes
killMbox

# All done
echo "[TEST] All done. Check files: log_server, log_mbox_*, log_client"
