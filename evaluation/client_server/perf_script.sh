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

# Get common functions with script <<perf_script.sh>>
source function.sh

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
protoList[4]="pln"
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


# Read mboxes (and server) address from config file 
# NOTE: no option 4 since it needs to update file first 
if [ $expType -ne 4 ] 
then
	readMboxes
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
		start_server
		
		# Start middleboxes 
		organizeMBOXES

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
		start_server

		# Start middleboxes 
		organizeMBOXES
		
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
		s=4
		strategy="cs"

		# Update res file 
		resFile=$resFile"_timeFirstByte_proxy"
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi

		# Start the server 
		start_server
		
		# Run S_MAX repetitions
		for((N=1; N<=N_MAX; N=2*N))
		do
			# Update proxy file 
			proxyFileUpdate 

			# Read proxy from (updated) file
			readMboxes

			# Start middleboxes 
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
		start_server

		# Start middleboxes 
		organizeMBOXES

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
		start_server
	
		# Start middleboxes 
		organizeMBOXES

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

	7)  
		echo "[PERF] Number of connections (f[#slices])"
		opt=1
		strategy="uni"
		testDur=10       
		pathOpenSSL="/usr/local/ssl/bin/openssl"
		s=4
		cipher="DHE-RSA-AES128-SHA256"
		#pathAppsLocal=$HOME"/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/apps"
        #pathAppsRemote="/home/$user/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/apps"

		# Update res file 
		resFile=$resFile"_connections_slice"
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi

		# Start the server 
		start_server
		
		# Start middleboxes 
		organizeMBOXES
		
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
				$pathOpenSSL s_time -connect $nextHop -new -time $testDur -proto $proto -slice $s -read 1 -write 1 -cipher $cipher >> $log 2>&1
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
		strategy="cs"

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
		
		scenarios[4,"numSlices"]=8
		scenarios[4,"numMboxes"]=1
		scenarios[4,"fileSize"]=1024

		scenarios[5,"numSlices"]=4
		scenarios[5,"numMboxes"]=1
		scenarios[5,"fileSize"]=10240

		let "numScenarios=${#scenarios[@]}/3"
		echo "[PERF] Testing $numScenarios scenarios"


		# Update res file 
		resFile=$resFile"_byteOverhead_scenarios"
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi

		# Start the server
		start_server
		
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
			cat $log | grep "ByteStatsSummary" | cut -f 3,4,5,6,7,8,9,10,11,12 -d " " | awk -f filter_scenarios.awk > $resFile
		else
			echo "[PERF] No file <<$log>> created, check for ERRORS!"
		fi
		;;

	*)	
		;;
esac 

# Cleanup
if [ $# -eq 9 ]
then
	echo "[PERF] Resetting network parameters (after experiment)"
	./network.sh 2
fi

# Kill the server
killServer

# Kill mboxes
killMbox
