#!/bin/bash 


# Function to print script usage
usage(){
    echo -e "Usage: $0 MAX_S MAX_R proto expType remote [rate[Mbps] max_rate[Mbps] delay[ms] iface[lo,eth0,...]"
    echo -e "MAX_S   = max number of slices (min is 2)"
    echo -e "MAX_R   = number of repetition of handshake per slice value"
    echo -e "proto   = protocol requested (ssl; spp; fwd)"
    echo -e "expType = {1=handshake (NOT USED) ; 2=ping-like (f[slices_len]) ; 3=ping-like (f[delay]); 4=ping-like (f[N_proxy]) ; 5=file download (f[size(1K-10MB)]) ; 6=browser-like behavior ; 7=test number of connections per second ; 8=byte analysis}"
    echo -e "remote =  {(0) local experiments (1) Amazon experiments}"
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

# Organize MBOXES, address, etc. 
organizeMBOXES(){
	
	firstLine=1    # flag for first line 
	count=1        # int for proxy ID
	nProxy=1       # number of proxies
	
	# Kill mbox pending
	killMbox
	
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
		if [ $proto == "ssl" -o $proto == "fwd" ]
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
[[ $# -lt 5 ]] && usage

# Parameters
S_MAX=$1                  # max number of slices
R=$2                      # number of repetitions per experiment
proto=$3                  # protocol to be used
expType=$4                # experiment type
log="log_perf"            # performance log file
MAX=16                    # hard coded max number of slices as per Kyle
fSizeMAX=5		          # max file size is 5MB
proxyFile="./proxyList"   # contains proxy information 
resFolder="../results"    # result folder        
resFile=$resFolder"/res"  # result file 
debug=0                   # more logging 
protoList[1]="ssl"        # array for protocol types currently supported
protoList[2]="fwd"
protoList[3]="spp"
#protoList[4]="spp_mod"
#-------------------------------REMOTE ADDITION
REMOTE=$5                   # 1=remote ; 0=local 
key="amazon.pem"           # amazon key 
user="ubuntu"              # amazon user 
remoteFolder="/home/$user/secure_proxy_protocol/evaluation/client_server" # remote folder
timeSleep=5                # time for server to setup
#-------------------------------REMOTE ADDITION

# Max file size in MB
let "fSizeMAX = fSizeMAX*1024*1024"

# derive proto size
proto_count=${#protoList[@]}

# Run few checks on input parameters
if [ $S_MAX -gt $MAX ] 
then 
	echo "[PERF] Currently max number of slices is $MAX"
	exit 0
fi

if [ $S_MAX -lt 2 ] 
then 
	echo "[PERF] Currently min number of slices is 2"
	exit 0
fi 

# check that protocol requested is supported
found=0
for ((i=1; i<=proto_count; i++))
do
	if [ $proto == "${protoList[$i]}" ] 
	then 
		found=1
	fi
done
if [ $found == 0 ]
then 
	echo "Protocol requested ($proto) is currently not supported"
	usage
fi

# Update result file name according to protocol requested 
resFile=$resFile"_"$proto
if [ $REMOTE -eq 1 ] 
then 
	resFile=$resFile"_remote"
fi

#Logging 
echo "[PERF] Sumary of user input -- Max_no_slices=$S_MAX ; rep=$R ; prot=$proto ; expType=$expType"


# Cleaning network parameters, just in case 
echo "[PERF] Cleaning network parameters (just in case)"
./network.sh 2 

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
if [ $# -gt 5 ]
then 
	if [ $# -lt 9 ]
	then 
		echo "[PERF] Running with no network config. For net conf. you need 4 optional parameters: [rate[Mbps] max_rate[Mbps] delay[ms] iface"
	else
		rate=$6
		maxRate=$7
		delay=$8
		iface=$9
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


# Start middlebox - and in proper way - if needed 
if [ $expType -ne 3 ]
then  
	organizeMBOXES
fi

# Make sure server is not running
killServer

# Switch among user choices
case $expType in 

	1)  # Test handshake duration 
		opt=2
		echo "[PERF] Test handshake only not used since hard to compare. Use insted option (2) which measures time to first bytes"
		;; 

	2)  # Test time to first byte 
		echo "[PERF] Test time to first byte (function of slice complexity)"
		opt=2
		strategy="uni"

		# Update res file 
		resFile=$resFile"_timeFirstByte_slice"
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi

		# Start the server 
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

		# Run S_MAX repetitions
		for((s=1; s<=S_MAX; s=2*s))
		do
			# Run R handshake repetitions	
			echo "[PERF] Testing $R handshakes with $s slices (protocol <<$proto>>)"
			for((i=1; i<=R; i++))
			do
				echo "[PERF] ./wclient -s $s -r 1 -w 1 -c $proto -o $opt >> $log 2>&1"
				./wclient -s $s -r 1 -w 1 -c $proto -o $opt >> $log 2>&1
			done
		done

		# Results
		if [ -f $log ] 
		then  
			if [ $debug -eq 1 ]
			then 
				echo "#Handshake Analysis" > $resFile
				echo "#Slices AvgDur StdDur" >> $resFile 
			fi
			#cat $log | grep Handshake_Dur | cut -f 3,7 -d " " | awk -v rtt=$delay -v N=$nProxy -f stdev.awk >> $resFile
			let "fix2=nProxy-1"
			cat $log | grep "Action" | cut -f 3,7 -d " " | awk -v fix1=$delay -v fix2=$fix2 -v S=1 -f stdev.awk > $resFile
		else
			echo "[PERF] No file <<$log>> created, check for ERRORS!"
		fi
		;;

	3)  # Test time to first byte 
		echo "[PERF] Test time to first byte (function of network latency). Max hop-by-hop delay="$MAX_DELAY"ms"
		
		# Parameters 
		MAX_DELAY=80     
		opt=2
		# 4 slices (1 req header, 1 req body) (1 resp header, 1 resp body)
		s=4
		strategy="cs"

		# Update res file 
		resFile=$resFile"_timeFirstByte_latency"
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi
		# Start the server 
		echo "[PERF] ./wserver -c $proto -o $opt"
		./wserver -c $proto -o $opt -s $strategy > log_server 2>&1 &

		# Give server small time to setup 
		sleep 1


		# Run client  along with network setup 
		for((delay=5; delay<=MAX_DELAY; delay=2*delay))
		do
			# Setup network delay 
			./network.sh 2 
			echo "[PERF] Setting up local network parameters - Rate=" $rate"Mbps MaxRate="$maxRate"Mbps Delay="$delay"ms Interface=$iface"
			./network.sh 1 $rate $maxRate $delay $iface

			# Run R handshake repetitions	
			echo "[PERF] Testing $R handshakes with delay $delay (3 slices:  for handshake, 1 for header, 1 for content)"
			for((i=1; i<=R; i++))
			do
				echo $delay >> .tmp 
				echo "[PERF] ./wclient -s $s -r 1 -w 1 -c $proto -o $opt"
				./wclient -s $s -r 1 -w 1 -c $proto -o $opt >> $log 2>&1
			done
		done

		# fixing log file 
		cat $log | grep "Action" | cut -f 7 -d " " > .tmpMore

		# Results
		if [ -f $log ] 
		then  
			if [ $debug -eq 1 ]
			then 
				echo "#Handshake Analysis" > $resFile
				echo "#Slices AvgDur StdDur" >> $resFile 
			fi
			paste .tmp .tmpMore > .res
			let "fix2=nProxy-1"
			cat .res  |  awk -v fix1=$s -v fix2=$fix2 -v S=5 -f stdev.awk > $resFile
			rm .tmp .tmpMore 
			#cat $log | grep "Action" | cut -f 3,7 -d " " | awk -v rtt=$delay -v N=$nProxy -f stdev.awk >> $resFile
		else
			echo "[PERF] No file <<$log>> created, check for ERRORS!"
		fi
		;;
	
	
	4)  # Test time to first byte [f(N_proxy])
		echo "[PERF] Test time to first byte (function of number of proxies [1:8])"
		opt=2
		N_MAX=8

		# Update res file 
		resFile=$resFile"_timeFirstByte_proxy"
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi

		# Start the server 
		echo "[PERF] ./wserver -c $proto -o $opt"
		./wserver -c $proto -o $opt -s $strategy > log_server 2>&1 &

		# Give server small time to setup 
		sleep 1

		# 4 slices (1 req header, 1 req body) (1 resp header, 1 resp body)
		s=4
		strategy="cs"

		# Make copy of current file 
		cp $proxyFile $proxyFile"_original"

		# Run S_MAX repetitions
		for((N=1; N<=N_MAX; N=2*N))
		do
			# Update proxy file 
			proxyFileUpdate 

			# Proxy setup 
			organizeMBOXES
			
			# Run R handshake repetitions	
			echo "[PERF] Testing $R handshakes with $N proxies (3 slices:  for handshake, 1 for header, 1 for content)"
			for((i=1; i<=R; i++))
			do
				# Logging for future correction
				echo $N >> .tmp 

				# Starting client 
				echo "[PERF] ./wclient -s $s -r 1 -w 1 -c $proto -o $opt"
				./wclient -s $s -r 1 -w 1 -c $proto -o $opt >> $log 2>&1
			done

			# Reset mboxes 
			killMbox
		done

		# Results
		if [ -f $log ] 
		then  
			if [ $debug -eq 1 ]
			then 
				echo "#Handshake Analysis" > $resFile
				echo "#Slices AvgDur StdDur" >> $resFile 
			fi
			let "fix2=nProxy-1"
			
			# fixing log file 
			cat $log | grep "Action" | cut -f 7 -d " " > .tmpMore
			paste .tmp .tmpMore > .res
			
			# Analyzing (corrected) log 
			cat .res  |  awk -v fix1=$s -v fix2=$delay -v S=1 -f stdev.awk > $resFile
			rm .tmp .tmpMore 
		else
			echo "[PERF] No file <<$log>> created, check for ERRORS!"
		fi

		# Restore original proxy file (user for other experiments)
		cp $proxyFile"_original" $proxyFile
		;;



	5)	# Measure download time as a function of file size
		echo "[PERF] Download time as a function of file size "
		opt=3
		# 4 slices (1 req header, 1 req body) (1 resp header, 1 resp body)
		s=4
		strategy="cs"
	
		# Update res file 
		resFile=$resFile"_downloadTime"

		# Cleaning
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi

		# Start the server 
		echo "[PERF] ./wserver -c $proto -o $opt"
		./wserver -c $proto -o $opt -s $strategy > log_server 2>&1 &
	
		# Give server small time to setup 
		sleep 1

		# Run until fSize is bigger than fSizeMAX
		fSizeInitial=40
		fSizeShort=$fSizeInitial
		let "fSize=fSizeShort*1024" #(10KB)
		while [ $fSize -le $fSizeMAX ]
		do 
			# Run R handshake repetitions	
			echo "Test $R file retrievals with file size $fSize ($s slices)"
			for((i=1; i<=R; i++))
			do
				echo $fSizeShort >> .tmp
				echo "[PER] ./wclient -s $s -c $proto -o $opt -f $fSize"
				#echo "./wclient -s $s -c $proto -o $opt -f $fSize >> $log 2>/dev/null"
				./wclient -s $s -c $proto -o $opt -f $fSize -r 1 -w 1 >> $log 2>/dev/null
			done
				let "fSize = 2*fSize"
				let "fSizeShort = 2*fSizeShort"
		done
		
		# Results
		if [ -f $log ] 
		then  
			if [ $debug -eq 1 ]
			then 
				echo "#Download Time Analysis" > $resFile
				echo "#FileSize Slices Delay AvgDur StdDur" >> $resFile 
			fi
			let "fix2=nProxy-1"
			
			# fixing log file 
			cat $log | grep "Action" | cut -f 7 -d " " > .tmpMore
			paste .tmp .tmpMore > .res
			
			# Analyzing (corrected) log 
			cat .res  |  awk -v fix1=$s -v fix2=$delay -v S=$fSizeInitial -f stdev.awk > $resFile
			rm .tmp .tmpMore 
		else
			echo "[PERF] No file <<$log>> created, check for ERRORS!"
		fi
		;;

	6)	# Measure download time in browser-like behavior 
		echo "[PERF] Measure download time in browser-like behavior"
		opt=4
		# 4 slices (1 req header, 1 req body) (1 resp header, 1 resp body)
		s=4
		strategy="cs"
	
		# Update res file 
		resFile=$resFile"_downloadTime_browser"

		# Cleaning
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi

		# Start the server 
		echo "[PERF] ./wserver -c $proto -o $opt"
		./wserver -c $proto -o $opt -s $strategy > log_server 2>&1 &
	
		# Give server small time to setup 
		sleep 1

		# Run until no action 
		actionFolder="../realworld_web/alexa500_https_2015-01-09/"
		loop=0
		MAX_LOOP=1
		for actionFile in `ls $actionFolder`	
		do 
			if [ $loop -eq $MAX_LOOP ] 
			then 
				echo "[PERF] Stopping since tested already <<$loop>> actionFiles"
				break 
			fi
			# Run R handshake repetitions	
			echo "[PERF] Test $R file retrievals with action file $fSize ($s slices)"
			for((i=1; i<=R; i++))
			do
				echo $loop >> .tmp
				#echo "[PERF] ./wclient -s $s -c $proto -o $opt -a $actionFile"
				echo "./wclient -s $s -c $proto -o $opt -a $actionFile >> $log 2>/dev/null"
			done
			let "loop++"
		done
		
		# Results
		if [ -f $log ] 
		then  
			if [ $debug -eq 1 ]
			then 
				echo "#Download Time Analysis" > $resFile
				echo "#Loop Slices Delay AvgDur StdDur" >> $resFile 
			fi
			let "fix2=nProxy-1"
			
			# fixing log file 
			cat $log | grep "Action" | cut -f 7 -d " " > .tmpMore
			paste .tmp .tmpMore > .res
			
			# Analyzing (corrected) log 
			cat .res  |  awk -v fix1=$s -v fix2=$delay -v S=0 -f stdev.awk > $resFile
			rm .tmp .tmpMore 
		else
			echo "[PERF] No file <<$log>> created, check for ERRORS!"
		fi
		;;

	7)  # Port to work remotely as well
		echo "[PERF] Number of connections (f[#slices])"
		opt=1
		strategy="uni"
		testDur=2       
		pathApps=$HOME"/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/apps"
		s=4
		cipher="DH"     # check this???
		#pathAppsLocal=$HOME"/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/apps"
        #pathAppsRemote="/home/$user/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/apps"

		# Update res file 
		resFile=$resFile"_connections_slice"
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi

		# Start the server 
		echo "[PERF] ./wserver -c $proto -o $opt"
		./wserver -c $proto -o $opt -s $strategy > log_server 2>&1 &

		# Give server small time to setup 
		sleep 1

		# Get next hop address 
		nextHop=`cat $proxyFile | awk '{if(count==1)print $0; count+=1}'`

		# Run S_MAX repetitions
		for((s=1; s<=S_MAX; s=2*s))
		do
			# Run R handshake repetitions	
			echo "[PERF] Testing $R handshakes with $s slices (worst case, all mboxes get READ/WRITE access)"
			for((i=1; i<=R; i++))
			do
				echo $s >> .tmp 
				#echo "$pathApps"/openssl" s_time -connect $nextHop -new -time $testDur -proto $proto -slice $s -read 1 -write 1 >> $log 2>&1"
				$pathApps"/openssl" s_time -connect $nextHop -new -time $testDur -proto $proto -slice $s -read 1 -write 1 -cipher $cipher >> $log 2>&1
			done
		done

		# Results
		if [ -f $log ] 
		then  
			if [ $debug -eq 1 ]
			then 
				echo "#Connection Analysis" > $resFile
				#echo "#Slices AvgDur StdDur" >> $resFile 
			fi
			#cat $log | grep Handshake_Dur | cut -f 3,7 -d " " | awk -v rtt=$delay -v N=$nProxy -f stdev.awk >> $resFile
			let "fix2=nProxy-1"
			
			# fixing log file 
			cat $log | grep connections | grep -v real | cut -f 5 -d " " >  .tmpMore
			paste .tmp .tmpMore > .res
			
			# Analyzing (corrected) log 
			cat .res  |  awk -v fix1=$delay -v fix2=$fix2 -v S=1 -f stdev.awk > $resFile
			rm .tmp .tmpMore 
		else
			echo "[PERF] No file <<$log>> created, check for ERRORS!"
		fi
		
		#echo "[PERF] Number of connctions (f[#proxies]) -- PENDING"
		;; 

	8) 
		echo "[PERF] Byte overhead -- X axis is a few discrete scenarios"
		opt=3

		# Define scenarios to test (num slices, num middleboxes, file size)
		declare -A scenarios
		scenarios[1,"numSlices"]=2  # TODO: make 1 after client fix
		scenarios[1,"numMboxes"]=0
		scenarios[1,"fileSize"]=1024
		
		scenarios[2,"numSlices"]=4
		scenarios[2,"numMboxes"]=0
		scenarios[2,"fileSize"]=1024

		scenarios[3,"numSlices"]=4
		scenarios[3,"numMboxes"]=1
		scenarios[3,"fileSize"]=1024

		let "numScenarios=${#scenarios[@]}/3"
		echo "[PERF] Testing $numScenarios scenarios"


		# Update res file 
		resFile=$resFile"_byteOverhead_scenarios"
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi

		# Start the server 
		set -x  # print commands we run
		./wserver -c $proto -o $opt -s cs > log_server 2>&1 &
		{ set +x; } 2>/dev/null  # stop printing commands

		# Give server small time to setup 
		sleep 1
		
		# Make copy of current file (not needed anymore)
		# cp $proxyFile $proxyFile"_original"

		# Run each scenario
		for((s=1; s<=$numScenarios; s++))
		do
			
			# Update proxy file 
			N=${scenarios[$s,"numMboxes"]}
			proxyFileUpdate 

			# Proxy setup 
			organizeMBOXES

			# Run R repetitions	of scenario s
			echo "[PERF] Testing $R reps with ${scenarios[$s,"numSlices"]} slices, ${scenarios[$s,"numMboxes"]} mboxes, ${scenarios[$s,"fileSize"]} byte file"
			for((i=1; i<=R; i++))
			do
				set -x  # print commands we run
				# FIXME: -r and -w should really be min(numSlices, numMboxes)
				./wclient -s ${scenarios[$s,"numSlices"]}\
					-r ${scenarios[$s,"numMboxes"]}\
					-w ${scenarios[$s,"numMboxes"]}\
					-f ${scenarios[$s,"fileSize"]}\
					-c $proto -o $opt -b 1 >> $log 2>&1
				{ set +x; } 2>/dev/null  # stop printing commands
			done
			
			# Reset mboxes 
			killMbox
		done
		
		# Restore original proxy file (used for other experiments)
		cp $proxyFile"_original" $proxyFile

		# Results
		if [ -f $log ] 
		then  
			if [ $debug -eq 1 ]
			then 
				echo "#Byte Overhead Analysis" > $resFile
				echo "#NumSlices NumMboxes FileSize TotalBytes AppTotal PaddingTotal HeaderTotal HandshakeTotal" >> $resFile 
			fi
			cat $log | grep "ByteStatsSummary" | cut -f 3,4,5,6,7,8,9,10 -d " " | awk -f filter_scenarios.awk > $resFile
		else
			echo "[PERF] No file <<$log>> created, check for ERRORS!"
		fi
		;;

	*)	
		;;
esac 


# Cleanup
if [ $# -eq 8 ]
then
	echo "[PERF] Resetting network parameters (after experiment)"
	./network.sh 2
fi

# Kill the server
killServer

# Kill mboxes
killMbox
