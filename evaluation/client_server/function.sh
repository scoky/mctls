#!/bin/bash 
# Kill eventual pending server processes 
killServer(){
	echo "[FUNCTION] Killing server"
	#killall -q wserver #>> /dev/null 2>&1
	if [ $REMOTE -eq 0 ]
	then  
		for i in `ps aux | grep wserver | grep -v vi | grep -v grep | awk '{print $2}'`
		do 
			echo "[FUNCTION] Killing wserver $i"
			kill -9 $i >> /dev/null 2>&1
		done
	else
		command="cd $remoteFolder; ./kill.sh"
		ssh -o StrictHostKeyChecking=no -i $key $user@$serverAdr $command 
	fi
}

# Kill eventual pending mbox processes
killMbox(){
	echo "[FUNCTION] Killing mbox"
	if [ $REMOTE -eq 0 ]
	then  
		#killall -q mbox #>> /dev/null 2>&1
		for i in `ps aux | grep mbox | grep -v vi | grep -v grep | awk '{print $2}'`
		do 
			echo "[FUNCTION] Killing mbox $i"
			kill -9 $i >> /dev/null  2>&1
		done
	else
		# Kill proxy according to protocol requestes 
		for ((i=1; i<nProxy; i++))
		do
			proxy=${proxyList[$i]}
			addr=`echo $proxy | cut -f 1 -d ":"`
			command="cd $remoteFolder; ./kill.sh"
			ssh -o StrictHostKeyChecking=no -i $key $user@$addr $command 
		done
	fi
}

# Start a server instance (either remote or local)
start_server(){
	echo "[FUNCTION] Starting server $serverAdr (port: $serverPort)"
	echo -e "\t./wserver -c $proto -o $opt -s $strategy -l $loadTime"
	if [ -f log_server ]
	then 
		rm log_server
	fi 
	if [ $REMOTE -eq 0 ] 
	then 
		./wserver -c $proto -o $opt -s $strategy -l $loadTime > log_server 2>&1 &
	else 
		command="cd $remoteFolder; ./wserver -c $proto -o $opt -s $strategy" 
		echo "ssh -o StrictHostKeyChecking=no -i $key $user@$serverAdr $command > log_server 2>&1 &"
		ssh -o StrictHostKeyChecking=no -i $key $user@$serverAdr $command > log_server 2>&1 &
	fi 
	
	# Give server some time to setup 
	echo "[FUNCTION] Sleeping $timeSleep to allow server setup"
	sleep $timeSleep
}

# Read mboxes and server addresses and ports 
readMboxes(){
	firstLine=1    # flag for first line 
	count=1        # int for proxy ID
	nProxy=1       # number of proxies
	
	# load proxy list in memory 
	while read line
	do 
		if [ $firstLine -eq 1 ] 
		then
			serverLine=$line
			let "nProxy=line-1"
			echo "[FUNCTION] Reading proxies info. We expect $nProxy proxies"
			firstLine=0
		else
			if [ $count -eq $serverLine ]
			then
				serverAdr=`echo $line | cut -f 1 -d ":"`
				serverPort=`echo $line | cut -f 2 -d ":"`
				proxyList[$count]=$line
				echo "[FUNCTION] Read server info (addr=$serverAdr ; port=$serverPort)"
			else
				if [ $count -eq 1 ] 
				then 
					mboxAdr=`echo $line | cut -f 1 -d ":"`
				fi
				proxyList[$count]=$line
				echo "[FUNCTION] Read proxy info (${proxyList[$count]})"
			fi
			let "count++"
		fi
	done < $proxyFile
}

# Start and organzie mboxes (routing) 
organizeMBOXES(){
	
	# Kill mbox pending
	killMbox

	# Start proxy according to protocol requested 
	echo "[FUNCTION] Starting $nProxy proxies:"
	for ((i=1; i<=nProxy; i++))
	do
		# Get data for this proxy 
		proxy=${proxyList[$i]}
		port=`echo $proxy | cut -f 2 -d ":"`
		addr=`echo $proxy | cut -f 1 -d ":"`
		
		# Get data for next proxy 
		let "j=i+1"
		nextProxy=${proxyList[$j]}
	
		# cleanup 
		if [ -f log_mbox_$port ] 
		then 
			rm log_mbox_$port
		fi
		
		# Start proxy with SPP 
		if [ $proto == "spp" -o $proto == "spp_mod" ]
		then
			# Logging 
			echo "[FUNCTION] Starting proxy $proxy (port: $port)"
			echo -e "\t./mbox -c $proto -p $port -m $proxy -l $loadTime"
			
			# Start!		
			if [ $REMOTE -eq 0 ] 
			then 
				./mbox -c $proto -p $port -m $proxy -l $loadTime >> log_mbox_$port 2>&1 &
			else 
				command="killall mbox"
				ssh -o StrictHostKeyChecking=no -i $key $user@$addr $command 
				command="cd $remoteFolder; ./mbox -c $proto -p $port -m $proxy"  
				ssh -o StrictHostKeyChecking=no -i $key $user@$addr $command  > log_mbox_$addr 2>&1 &
			fi
		fi
		
		# Start proxy with SSL
		if [ $proto == "ssl" -o $proto == "fwd" -o $proto == "pln" -o $proto == "ssl_mod" -o $proto == "fwd_mod" -o $proto == "pln_mod" ]
		then 
			# Logging 
			echo "[FUNCTION] Starting proxy $proxy (port extracted: $port - Next proxy: $nextProxy)"
			echo -e "\t./mbox -c $proto -p $port -m $proxy -a $nextProxy -l $loadTime"
			
			# Start!		
			if [ $REMOTE -eq 0 ] 
			then 
				./mbox -c $proto -p $port -m $proxy -a $nextProxy -l $loadTime >> log_mbox_$port 2>&1 &
			else
				command="killall mbox"
				ssh -o StrictHostKeyChecking=no -i $key $user@$addr $command 
				command="cd $remoteFolder; ./mbox -c $proto -p $port -m $proxy -a $nextProxy"
				echo "[FUNCTION] ssh -i $key $user@$addr $command > log_mbox_$addr 2>&1 &"
				ssh -o StrictHostKeyChecking=no -i $key $user@$addr $command > log_mbox_$addr 2>&1 &
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
	echo "[FUNCTION] Proxy file genereated is: "
	cat $proxyFile
}


# Load scenarios from file to memory
load_scenarios(){
	first=1        # flag for first line

	# load proxy list in memory 
	while read line
	do
		i=`echo $line | cut -f 1 -d " "`
		if [ $first -eq 1 ] 
		then 
			initScen=$i
			first=0
		fi
		label=`echo $line | cut -f 2 -d " "`
		value=`echo $line | cut -f 3 -d " "`
		scenarios[$i,$label]=$value
		echo "[FUNCTION] Added entry scenarios[$i,$label]=$value"
	done < $scenFile
}


