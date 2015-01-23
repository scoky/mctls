#!/bin/bash 


# Function to print script usage
usage(){
    echo -e "Usage: $0 opt s proto remote [rate[Mbps] max_rate[Mbps] delay[ms] iface[lo,eth0,...]"
    echo -e "opt = {(1) (2) (3) (4) (5) (6) (7) (8)}"
	echo -e "\t(1) Test handshake "
	echo -e "\t(2) Test time to first byte"
	echo -e "\t(3) Test N proxies (N=4)"
	echo -e "\t(4) Test file download (1MB)"
	echo -e "\t(5) Test number of connection per second"
    echo -e "s      = number of slices"
    echo -e "proto  = protocol to be used"
    echo -e "remote = {(0) local experiments (1) Amazon experiments}"
    echo -e "[optional parameters require <<tc>>, ok on Amazon"
    exit 0
}

# Kill eventual pending server processes 
killServer(){
	echo "[PERF] Killing server"
	#killall -q wserver #>> /dev/null 2>&1
	if [ $REMOTE -eq 0 ]
	then  
		for i in `ps aux | grep wserver | grep -v vi | grep -v grep | awk '{print $2}'`
		do 
			echo "Killing wserver $i"
			kill -9 $i >> /dev/null 2>&1
		done
	else
		command="cd $remoteFolder; ./kill.sh"
		ssh -i $key $user@$serverAdr $command 
	fi
}

# Kill eventual pending mbox processes
killMbox(){
	echo "[PERF] Killing mbox"
	if [ $REMOTE -eq 0 ]
	then  
		#killall -q mbox #>> /dev/null 2>&1
		for i in `ps aux | grep mbox | grep -v vi | grep -v grep | awk '{print $2}'`
		do 
			echo "[PERF] Killing mbox $i"
			kill -9 $i >> /dev/null  2>&1
		done
	else
		# Kill proxy according to protocol requestes 
		for ((i=1; i<nProxy; i++))
		do
			proxy=${proxyList[$i]}
			addr=`echo $proxy | cut -f 1 -d ":"`
			command="cd $remoteFolder; ./kill.sh"
			ssh -i $key $user@$addr $command 
		done
	fi
}

# Start a server instance (either remote or local)
start_server(){
	echo "[PERF] Starting server: ./wserver -c $proto -o $opt -s $strategy"
	if [ $REMOTE -eq 0 ] 
	then 
		./wserver -c $proto -o $opt -s $strategy > log_server 2>&1 &
	else 
		command="cd $remoteFolder; ./wserver -c $proto -o $opt -s $strategy" 
		ssh -o StrictHostKeyChecking=no -i $key $user@$serverAdr $command > log_server 2>&1 &
	fi 
	
	# Give server some time to setup 
	echo "[PERF] Sleeping $timeSleep to allow server setup"
	sleep $timeSleep
}

# Read mboxes and server addresses and ports 
readMboxes(){
	firstLine=1    # flag for first line 
	count=1        # int for proxy ID
	nProxy=1       # number of proxies
	
	
	# load proxy list in memory 
	while read proxy
	do 
		if [ $firstLine -eq 1 ] 
		then
			if [ $proxy == "1" ] 
			then 
				break 
			else
				nProxy=$proxy
				firstLine=0
			fi
		else	
			if [ $count -eq $nProxy ]
			then
				serverAdr=`echo $proxy | cut -f 1 -d ":"`
				serverPort=`echo $proxy | cut -f 2 -d ":"`
			fi
			proxyList[$count]=$proxy
			let "count++"
		fi
	done < $proxyFile
}

# Start and organzie mboxes (routing) 
organizeMBOXES(){
	
	# Kill mbox pending
	killMbox
	
	# Start proxy according to protocol requested 
	for ((i=1; i<nProxy; i++))
	do
		# Get data for this proxy 
		proxy=${proxyList[$i]}
		port=`echo $proxy | cut -f 2 -d ":"`
		addr=`echo $proxy | cut -f 1 -d ":"`
		
		# Get data for next proxy 
		let "j=i+1"
		nextProxy=${proxyList[$j]}
		
		# Start proxy with SPP 
		if [ $proto == "spp" -o $proto == "spp_mod" ]
		then
			# Logging 
			echo "[PERF] Starting proxy $proxy (port extracted: $port)"
			
			# Start!		
			if [ $REMOTE -eq 0 ] 
			then 
				./mbox -c $proto -p $port -m $proxy > log_mbox_$port 2>&1 &
			else 
				command="killall mbox"
				ssh -i $key $user@$addr $command 
				command="cd $remoteFolder; ./mbox -c $proto -p $port -m $proxy"  
				ssh -i $key $user@$addr $command  > log_mbox_$addr 2>&1 &
			fi
		fi
		
		# Start proxy with SSL
		if [ $proto == "ssl" -o $proto == "fwd" -o $proto == "pln" ]
		then 
			# Logging 
			echo "[PERF] Starting proxy $proxy (port extracted: $port - Next proxy: $nextProxy)"
			
			# Start!		
			if [ $REMOTE -eq 0 ] 
			then 
				./mbox -c $proto -p $port -m $proxy -a $nextProxy > log_mbox_$port 2>&1 &
			else
				command="killall mbox"
				ssh -i $key $user@$addr $command 
				command="cd $remoteFolder; ./mbox -c $proto -p $port -m $proxy -a $nextProxy"
				echo "[DEBUG] ssh -i $key $user@$addr $command > log_mbox_$addr 2>&1 &"
				ssh -i $key $user@$addr $command > log_mbox_$addr 2>&1 &
			fi
		fi
	done

	# Sleep 1 second (for David)  
	sleep 1
}


# Here updating proxy list 
proxyFileUpdate(){

	# parameters
	server_add="127.0.0.1"    # default server address 
	server_port="4433"        # default server port 
	address="127.0.0.1"       # default proxy address (TO DO -- extend to array if multiple machines used)
	nextPort=8423             # proxy starting port 

	# derive and print total number of network elements (N proxies + 1 server)
	let "tot=N+1"             
	echo $tot > $proxyFile

	# Generating lines for proxy
	for((i=1; i<=N; i++))
		do
			echo "$address:$nextPort" >> $proxyFile
			let "nextPort++"
		done

	echo "$server_add:$server_port" >> $proxyFile
}

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
readMboxes

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
		./wclient -s $s -r 1 -w 1 -c $proto -o $opt >> $log 2>&1
		;;
	
	
	3)  # Test N  proxies 
		echo "[TEST] Test N proxies (N=4)"
		echo "[TEST] !!Still debugging!!"
		exit 0 
		if [ $REMOTE -eq 1 ] 
		then 
			echo "[TEST] ERROR - Only two Amazon machines available, i.e., cannot test N proxies (N=4). Run locally!"
			exit 0 
		fi
		opt=2
		N=4
		
		# Start the server 
		start_server
		
		# Make copy of current file 
		cp $proxyFile $proxyFile"_original"

		# Update proxy file 
		proxyFileUpdate 

		# Start middleboxes 
		organizeMBOXES
			
		# Starting client 
		echo "[TEST] Client started" 
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
		./wclient -s $s -c $proto -o $opt -f $fSize -r 1 -w 1 >> $log 2>/dev/null
		;;	

	5)  # Test number of connection per second  
		echo "[TEST] Test number of connection per second (last 10 seconds)"
		opt=1
		testDur=10       
		pathOpenSSL="/usr/local/ssl/bin/openssl"
		cipher="DH"     # check this???

		# Start the server 
		start_server
		
		# Start middleboxes 
		organizeMBOXES
		
		# Get next hop address 
		nextHop=`cat $proxyFile | awk '{if(count==1)print $0; count+=1}'`

		# Start the client 
		echo "[TEST] Start s_time utility"
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
