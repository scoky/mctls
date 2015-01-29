#!/bin/bash 


# Function to print script usage
usage(){
    echo -e "Usage: $0 MAX_S MAX_R proto expType remote resFold [rate[Mbps] max_rate[Mbps] delay[ms] iface[lo,eth0,...]"
    echo -e "MAX_S   = max number of slices (min is 2)"
    echo -e "MAX_R   = number of repetition of handshake per slice value"
    echo -e "proto   = protocol requested (ssl; spp; fwd)"
    echo -e "expType = {1=handshake (NOT USED) ; 2=ping-like (f[slices_len]) ; 3=ping-like (f[delay]); 4=ping-like (f[N_proxy]) ; 5=file download (f[size(1K-10MB)]) ; 6=browser-like behavior ; 7=test number of connections per second ; 8=byte analysis 9=file download by scenarios (f[size, rate, remote)}"
    echo -e "remote  =  {(0) local experiments (1) Amazon experiments}"
    echo -e "resFold =  folder where results should be stored"
    exit 0
}

# Get common functions with script <<perf_script.sh>>
source function.sh

# Check input for minimum number of parameteres requestes
nReqParam=6
let "totParam=nReqParam+4"
[[ $# -lt $nReqParam ]] && usage

# Parameters
S_MAX=$1                   # max number of slices
R=$2                       # number of repetitions per experiment
proto=$3                   # protocol to be used
expType=$4                 # experiment type
REMOTE=$5                  # 1=remote ; 0=local 
resFolder=$6               # result folder        
log="log_perf_"$proto      # performance log file
MAX=16                     # hard coded max number of slices as per Kyle
fSizeMAX=5		           # max file size is 5MB
proxyFile="./proxyList"    # contains proxy information 
resFile=$resFolder"/res"   # result file 
debug=0                    # more logging 
delay=-1                   # default delay (-1 means no delay) 
loadTime=0                 # this disable by default logiing of CPU time 
protoList[1]="ssl"         # array for protocol types currently supported
protoList[2]="fwd"
protoList[3]="spp"
protoList[4]="pln"
protoList[5]="ssl_mod"      
protoList[6]="fwd_mod"
protoList[7]="spp_mod"
protoList[8]="pln_mod"
key="amazon.pem"           # amazon key 
user="ubuntu"              # amazon user 
remoteFolder="/home/$user/secure_proxy_protocol/evaluation/client_server" # remote folder
timeSleep=5                # time for server to setup

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
if [ $# -gt $nReqParam ]
then 
	if [ $# -lt $totParam ]
	then 
		echo "[PERF] Running with no network config. For net conf. you need 4 optional parameters: [rate[Mbps] max_rate[Mbps] delay[ms] iface"
	else
		c=$((nReqParam+1))
		rate=${!c}
		c=$((nReqParam+2))
		maxRate=${!c}
		c=$((nReqParam+3))
		delay=${!c}
		c=$((nReqParam+4))
		iface=${!c}
		echo "[PERF] Setting up local network parameters - Rate=" $rate"Mbps MaxRate="$maxRate"Mbps Delay="$delay"ms Interface=$iface"
		./network.sh 1 $rate $maxRate $delay $iface
		echo "[PERF] Veryfying network configuration"
		if [ $iface == "lo" ] 
		then 
			ping -c 3 localhost
		fi
	fi
else
	if [ $expType -ne 9 ] 
	then 
		echo "[PERF] Experiment requested overwrite network parameters as it runs on scenarios from file <<$scen_file>>"
	else
		echo "[PERF] Running with no network config. For net conf. you need 4 optional parameters: [rate[Mbps] max_rate[Mbps] delay[ms] iface"
	fi
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
		comm="ping"
		
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

		# Estimate RTT
		if [ $REMOTE -eq 1 ]
		then 
			echo "[MASTER] Start RTT estimation script"
			(./ping_script.sh $comm &)
		fi

		# Run S_MAX repetitions
		#for((s=1; s<=S_MAX; s=2*s))
		for((s=1; s<=S_MAX; s++))
		do
			# Run R handshake repetitions	
			echo "[PERF] Testing $R handshakes with $s slices (protocol <<$proto>>)"
			for((i=1; i<=R; i++))
			do
				#echo "[PERF] ./wclient -s $s -r $nProxy -w $nProxy -c $proto -o $opt >> $log 2>&1"
				./wclient -s $s -r $nProxy -w $nProxy -c $proto -o $opt >> $log 2>&1
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
			let "fix2=nProxy"
			cat $log | grep "Action" | cut -f 3,7 -d " " | awk -v fix1=$delay -v fix2=$fix2 -v S=1 -f stdev.awk > $resFile
			
			# paste RTT results if needed
			if [ $REMOTE -eq 1 ]
			then 
				if [ -f .tempPing ] 
				then 
					rm .tempPing
				fi
				if [ -f pingSummary ]
				then
					for((s=1; s<=S_MAX; s=2*s))
					do
						cat pingSummary >> .tempPing
					done
					paste $resFile .tempPing > .pasteRes
					mv .pasteRes $resFile
					rm .tempPing
				else
					echo "[PERF] Error no file <<pingSummary>> was created, check for ERRORS in script <<ping_script.sh>>!"
				fi
			fi
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
		initDelay=5
		for((delay=initDelay; delay<=MAX_DELAY; delay=2*delay))
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
				#echo "[PERF] ./wclient -s $s -r $nProxy -w $nProxy -c $proto -o $opt"
				./wclient -s $s -r $nProxy -w $nProxy -c $proto -o $opt >> $log 2>&1
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
			let "fix2=nProxy"
			cat .res  |  awk -v fix1=$s -v fix2=$fix2 -v S=$initDelay -f stdev.awk > $resFile
			rm .tmp .tmpMore 
			#cat $log | grep "Action" | cut -f 3,7 -d " " | awk -v rtt=$delay -v N=$nProxy -f stdev.awk >> $resFile
		else
			echo "[PERF] No file <<$log>> created, check for ERRORS!"
		fi
		;;
	
	
	4)  # Test time to first byte [f(N_proxy])
		echo "[PERF] Test time to first byte (function of number of proxies [1:8])"
		opt=2
		N_MAX=16
		s=4
		strategy="cs"
		N_low=1

		# Update res file 
		resFile=$resFile"_timeFirstByte_proxy"
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi

		# Start the server 
		start_server
		
		# Run S_MAX repetitions
		for((N=$N_low; N<=N_MAX; N=2*N))
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
				#echo "[PERF] ./wclient -s $s -r $nProxy -w $nProxy -c $proto -o $opt >> $log 2>&1"
				./wclient -s $s -r $nProxy -w $nProxy -c $proto -o $opt >> $log 2>&1
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
			let "fix2=nProxy"
			
			# fixing log file 
			cat $log | grep "Action" | cut -f 7 -d " " > .tmpMore
			paste .tmp .tmpMore > .res
			
			# Analyzing (corrected) log 
			cat .res  |  awk -v fix1=$s -v fix2=$delay -v S=$N_low -f stdev.awk > $resFile
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
				#echo "[PERF] ./wclient -s $s -c $proto -o $opt -f $fSize -r $nProxy -w $nProxy >> $log 2>/dev/null"
				./wclient -s $s -c $proto -o $opt -f $fSize -r $nProxy -w $nProxy >> $log 2>/dev/null
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
			let "fix2=nProxy"
			
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
		MAX_LOOP=2
		opt=4
		strategy="cs"
		actionFolder="../realworld_web/alexa500_https_2015-01-09/"
		browser_fold="./browser"
		mkdir -p $browser_fold
		rm $browser_fold"log_perf_"*
		
		# test with specif subset of files 
		#expSlice[0]="one"
		#expSlice[0]="four"
		expSlice[0]="all"
		
		# Cleaning 
		if [ -f .tmp ] 
		then
			rm .tmp
		fi
		if [ -f .tmpMore ] 
		then
			rm .tmpMore
		fi

		# Start the server 
		start_server
	
		# Start middleboxes 
		organizeMBOXES

		# Start loop among input files 
		loop=0
		th=10
		counter=1
		
		# external loop on subset of files
		k_count=${#expSlice[@]}
		for ((j=0; j<k_count; j++))
		do
			str=${expSlice[j]}
			if [ $str == "one" ] 
			then 
				k="one-slice"
			fi
			if [ $str == "four" ] 
			then 
				k="four-slices"
			fi
			if [ $str == "all" ] 
			then 
				k="slice-per-header"
			fi

			# Update res file 
			resFileK=$resFile"_"$k"_page_load_time"
			resTraces=$resFolder"/res_traces_"$k"_page_load_time"
			
			# Cleaning
			if [ -f $resFileK ] 
			then 
				rm -v $resFileK
			fi
			if [ -f $resTraces ] 
			then 
				rm -v $resTraces
			fi

			# Logging 
			echo "[PERF] Measure download time in browser-like behavior. Max loop = $MAX_LOOP. Traces with key $k"

			for f in `ls $actionFolder | grep "$k"`    
			do
				echo "[PERF] Working on action file $f"
				if [ $loop -eq $MAX_LOOP ] 
				then 
					echo "[PERF] Stopping since tested already <<$loop>> actionFiles"
					break 
				fi
				
				# cleanup + prepare 1 file per connection 
				for i in `ls ./actionFiles`
				do
					rm "./actionFiles/"$i
				done
				N_clients=`cat $actionFolder"/"$f | awk '{if (conn[$NF] == 0){conn[$NF] = 1; count = count + 1;}}END{print count}'`
				
				# update download time from traces 
				tail -n 1 $actionFolder"/"$f | cut -f 1 -d " " >>  $resTraces
				
				# filter last bogus object 
				let "N_clients--"
				
				if [ $N_clients -gt $th ] 
				then 
					echo "[PERF] File $f skipped since it requires more than $th connections"
					continue
				else
					echo "[PERF] $N_clients connections were found"
					if [ $N_clients -eq 1 ]
					then
						# Compute number of objects requested in that single connection  
						N_objects=`wc -l $actionFolder"/"$f | cut -f 1 -d " "`
						
						# filter last bogus object  (not there anymore)
						#let "N_objects--"
						
						if [ $N_objects -eq 1 ]
						then 
							echo "[PERF] File $f skipped since it contains only $N_clients connection with $N_objects object"
							continue 
						else
							echo "[PERF] File $f contains $N_clients connection with $N_objects objects"
						fi
					fi	
				fi
				# retrieve site name 
				suff=`echo $f | cut -f 1 -d "_" | awk 'BEGIN{FS="---";}{print $2}'`
				
				# split per connection 
				cat $actionFolder"/"$f | awk '{if (NF>0){print $0 >> "./actionFiles/conn_"$NF}}'
				N_clients=0
			
				# Compute number of slices needed 
				s=`head -n 1 "./actionFiles/conn_0" | cut -f 2 -d " " | cut -f 1 -d ";" | awk 'BEGIN{FS="_";}{print NF}'`
				echo "[PERF] $s slices extracted from action file"
				
				# Starting all clients needed
				for i in `ls ./actionFiles`
				do
					#echo $loop >> .tmp
					let "N_clients++"
					echo "[PERF] ./wclient -s $s -r $nProxy -w $nProxy -c $proto -o $opt -a "./actionFiles/"$i"
					# parallel
					(./wclient -s $s -r $nProxy -w $nProxy -c $proto -o $opt -a "./actionFiles/"$i > $browser_fold"/"$log"_"$k"_"$suff"_"$i 2>/dev/null &)
					# sequential (for testing) 
					#./wclient -s $s -r $nProxy -w $nProxy -c $proto -o $opt -a "./actionFiles/"$i >> log_test_browser
					#echo $counter >> counter_test_browser
					let "counter++"
				done
				# Logging 
				echo "[PERF] Started $N_clients in parallel"
				active=`ps aux | grep wclient | grep actionFiles | grep -v grep | wc -l`
				while [ $active -gt 0 ] 
				do 
					echo "[PERF] Still $active clients running (sleeping 1 sec)"
					sleep 1
					active=`ps aux | grep wclient | grep actionFiles | grep -v grep | wc -l`
				done
				
				# Wait for all connections to be done than compute page load time (max across)
				cat $browser_fold"/"$log"_"$k"_"$suff"_"* | awk 'BEGIN{MAX = 0;}{if($NF > MAX){MAX = $NF;}}END{print MAX}' >> .tmpMore
				let "loop++"
				echo $delay $nProxy >> .tmp

			done
			
		
			# Merge results for plotting
			paste .tmp .tmpMore > $resFileK
			rm .tmp .tmpMore
		done
		
		# All good 
		echo "[PERF] All good -- check logs $log"_browser_* in folder $browser_fold")!!"
		;;

	7)  
		echo "[PERF] Number of connections (f[#slices]) -- FIXME: only work with 1 mbox at port 8423"
		opt=1
		strategy="uni"
		testDur=30      
		pathOpenSSL="/usr/local/ssl/bin/openssl"
		s=4
		cipher="DHE-RSA-AES128-SHA256"
		loadTime=10   # this enables logging of CPU time (in the future measure for that time?)
		
		prev_server=0;  # number of lines in server log from previous exp
		prev_mbox=0;    # number of lines in mbox log from previous exp

		# cleanup 
		if [ -f .resServer ] 
		then 
			rm .resServer
		fi
		if [ -f .resMbox ] 
		then 
			rm .resMbox
		fi
		
		# Update res file 
		resFileC=$resFile"_connections_slice_client"
		resFileM=$resFile"_connections_slice_mbox"
		resFileS=$resFile"_connections_slice_server"
		if [ -f $resFileC ] 
		then 
			rm -v $resFileC
		fi
		if [ -f $resFileM ] 
		then 
			rm -v $resFileM
		fi
		if [ -f $resFileS ] 
		then 
			rm -v $resFileS
		fi

		# create folder if needed 
		mkdir -p full_results

		# Start the server 
		start_server
		
		# Start middleboxes 
		organizeMBOXES
		
		# Get next hop address 
		nextHop=`cat $proxyFile | awk '{if(count==1)print $0; count+=1}'`

		# Run S_MAX repetitions
		minS=1
		#minS=8
		#echo "[PERF] !!!!Temporarly checking linear range from 8 to 16!!!!"
		for((s=$minS; s<=S_MAX; s=2*s))
		#for((s=$minS; s<=16; s++))
		do
			# Prepare for copy of full log 
			fullLogC="./full_results/results_client_$proto"
			fullLogM="./full_results/results_mbox_$proto"
			fullLogS="./full_results/results_server_$proto"
			
			# Run R handshake repetitions	
			echo "[PERF] Run $R s_time based tests ($s slices, all mboxes get READ/WRITE access)"
			for((i=1; i<=R; i++))
			do
				echo "[PERF] Test $i"
				echo $s >> .tmp 
				#echo "$pathApps"/openssl" s_time -connect $nextHop -new -time $testDur -proto $proto -slice $s -read 1 -write 1 >> $log 2>&1"
				$pathOpenSSL s_time -connect $nextHop -new -time $testDur -proto $proto -slice $s -read $nProxy -write $nProxy -cipher $cipher >> $log 2>&1
				# Analyzing and cleaning logs
				#cat log_server | awk '{split($2, a, "="); sum=sum+a[2]; c=c+1;}END{print c " connections. CPU time="sum"s;" c/sum " connections/user sec"}'
				curr_server=`wc -l log_server | cut -f 1 -d " "`
				curr_mbox=`wc -l log_mbox_8423 |  cut -f 1 -d " "`
				let "lines_s = curr_server - prev_server"
				let "lines_m = curr_mbox - prev_mbox"
				prev_server=$curr_server	
				prev_mbox=$curr_mbox
				
				#echo "tail -n $lines_s log_server"
				tail -n $lines_s log_server    | awk -v s=$s '{split($2, a, "="); sum=sum+a[2]; c=c+1;}END{print s " " c/sum}' >> .resServer
				#echo "tail -n $lines_m log_mbox"
				tail -n $lines_m log_mbox_8423 | awk -v s=$s '{split($2, a, "="); sum=sum+a[2]; c=c+1;}END{print s " " c/sum}' >> .resMbox
			done
		done

		# Results
		if [ -f $log ] 
		then  
			if [ $debug -eq 1 ]
			then 
				echo "#Connection Analysis" > $resFileC
				echo "#Connection Analysis" > $resFileM
				echo "#Connection Analysis" > $resFileS
			fi
			let "fix2=nProxy"
			
			# fixing log file 
			cat $log | grep connections | grep -v real | cut -f 5 -d " " >  .tmpMore
			paste .tmp .tmpMore > .res
			
			# Analyzing (corrected) log 
			cat .res  | grep -v -i inf | awk -v fix1=$delay -v fix2=$fix2 -v S=$minS -f stdev.awk > $resFileC
			cat .resServer  | grep -v -i inf | awk -v fix1=$delay -v fix2=$fix2 -v S=$minS -f stdev.awk > $resFileM
			cat .resMbox  | grep -v -i inf | awk -v fix1=$delay -v fix2=$fix2 -v S=$minS -f stdev.awk > $resFileS

			# Make a local copy of full results 
			mv .res $fullLogC
			mv .resServer $fullLogS
			mv .resMbox $fullLogM
			
			# Cleanup support files
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
		scenarios[1,"numSlices"]=2
		scenarios[1,"numMboxes"]=0
		scenarios[1,"fileSize"]=$((10*1024))
		
		scenarios[2,"numSlices"]=4
		scenarios[2,"numMboxes"]=0
		scenarios[2,"fileSize"]=$((10*1024))
		
		scenarios[3,"numSlices"]=8
		scenarios[3,"numMboxes"]=0
		scenarios[3,"fileSize"]=$((10*1024))

		scenarios[4,"numSlices"]=4
		scenarios[4,"numMboxes"]=1
		scenarios[4,"fileSize"]=$((10*1024))
		
		scenarios[5,"numSlices"]=4
		scenarios[5,"numMboxes"]=2
		scenarios[5,"fileSize"]=$((10*1024))

		scenarios[6,"numSlices"]=4
		scenarios[6,"numMboxes"]=1
		scenarios[6,"fileSize"]=$((20*1024))

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
			
			# Read proxy from (updated) file
			readMboxes

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

	
	9) 
		echo "[PERF] Time to first byte (f[scenarios])"
		opt=3
		strategy="cs"
		delay=20               # default delay 
		iface="lo"             # default network interface
		
		#------------------------
		timeSleep=3
		R=10
		echo "[PERF] Default param: Rep=$R ; Delay=$delay (for LOCAL). Reducing server sleeping time to $timeSleep (CHECK)"
		#-----------------------

		## File sizes percentile from Alexa
		#10th percentile:        470.000000 B  			<--------
		#25th percentile:        1473.250000 B
		#50th percentile:        5009.000000 B			<--------
		#75th percentile:        16201.000000 B
		#90th percentile:        42101.000000 B
		#99th percentile:        190073.900000 B		<--------
		##
		## Avg from YouTube
		#	10MB										<--------
		## Speed from SpeedTets [1, 10, 100]Mbps

		## Download speed (rate) from speedtest (1, 10, 100Mbps)
		# Define scenarios to test (file size, rate, local/remote)
		declare -A scenarios
		scenFile="./scenarios"     # file containing scenarios to run 
		load_scenarios
		
		let "numScenarios=${#scenarios[@]}/4"
		let "endScen=initScen + numScenarios"

		# Update res file 
		resFile=$resFile"_timeFirstByte_scenarios"
		
		# Logging
		echo "[PERF] Testing $numScenarios scenarios. From id $initScen to id $endScen Results go in $resFile"
		
		# Cleaning
		if [ -f $resFile ] 
		then 
			rm -v $resFile
		fi
		if [ -f .tmp ] 
		then 
			rm -v .tmp
		fi
		if [ -f .tmpMore ] 
		then 
			rm -v .tmpMore
		fi
	
		# Set to crazy value so sure server and mbox are started on first run 	
		prevRemote=2

		# Run each scenario
		for((s=initScen; s<endScen; s++))
		do
			# Extract file size 
			fSize=${scenarios[$s,"fileSize"]}

			# Extract rate 	
			rate=${scenarios[$s,"rate"]}

			# Extract interface 
			iface=${scenarios[$s,"iface"]}

			# Setup network if not remote 
			REMOTE=${scenarios[$s,"remote"]}

			# Logging 
			if [ $REMOTE -eq 0 ]
			then
				echo -e "$(tput setaf 1)[PERF] Testing scenario $s -- File Size=$fSize ; Rate=$rate; Interface=$iface ; LOCAL$(tput sgr0)"
			else
				echo -e "$(tput setaf 1)[PERF] Testing scenario $s -- File Size=$fSize ; Interface=$iface ; AMAZON$(tput sgr0)"
			fi
			
			# Setup 	
			if [ $REMOTE -eq 0 ]
			then 
				cp $proxyFile"_original" $proxyFile 
				echo "[PERF] Organizing local network with parameters <<./network.sh 1 $rate $rate $delay $iface>>"
				./network.sh 1 $rate $rate $delay $iface
				if [ $iface == "lo" ] 
				then 
					ping -c 3 localhost
				fi
			else 
				cp $proxyFile"_amazon" $proxyFile
			fi	

			# Read proxy and server from (updated) file
			readMboxes
			
			# Add route to use 3G if requested 
			if [ $iface == "ppp0" ] 
			then 
				echo "[PERF] Setting up 3G route -- <<sudo route add $mboxAdr dev ppp0>>"
				sudo route add $mboxAdr dev ppp0
				sleep 2 
				ping -c 3 $mboxAdr
			fi

			# Start server and mboxes ? 
			if [ $prevRemote -ne $REMOTE ] 
			then
				# Start the server
				start_server

				# Proxy setup 
				organizeMBOXES
			else 
				echo "[PERF] Not restarting server and mboxes since current scenario is on same location as previous (prevRemote=$prevRemote ; currRemote=$REMOTE)"
			fi

			# Run R repetitions	of scenario s
			for((i=1; i<=R; i++))
			do
				echo $fSize $rate $REMOTE >> .tmp
				echo "Starting client"
				echo -e "\t ./wclient -s 4 -r 1 -w 1 -f $fSize -c $proto -o $opt -b 1"
				./wclient -s 4 -r 1 -w 1 -f $fSize -c $proto -o $opt -b 1 >> $log 2>&1
			done
	
			# cleanup the local network if not remote
			if [ $REMOTE -eq 0 ]
			then 
				echo "[PERF] Cleaning local network parameters"
				./network.sh 2
			fi
			
			# Cleanup 3G route in case
			if [ $iface == "ppp0" ] 
			then 
				echo "[PERF] Re-setting 3G route -- <<sudo route del $mboxAdr dev ppp0>>"
				sudo route del $mboxAdr dev ppp0
				sleep 2 
				ping -c 3 $mboxAdr
			fi
			
			let "lastS=endScen-1"
			if [ $s -ne $lastS ]
			then
				let "j=s+1"
				nextRemote=${scenarios[$j,"remote"]}
				if [ $nextRemote -ne $REMOTE ]
				then 	
					echo "[PERF] Killing server and mbox since next scenaro is on a different location (currRemote=$REMOTE ; nextRemote=$nextRemote)"
					# Kill the server
					killServer
					# Kill mboxes
					killMbox
				fi
			else
				echo "[PERF] All scenario completed  - Killing server and mbox"
				# Kill the server
				killServer
				# Kill mboxes
				killMbox
			fi
			# Save previous remote information to decide whether to start the server or not   
			prevRemote=$REMOTE
			
		done
			
		# Results
		if [ -f $log ] 
		then  
			if [ $debug -eq 1 ]
			then 
				echo "#Time to first byte Analysis" > $resFile
				echo "#FileSize Rate Remote Duration" >> $resFile 
			fi
			# fixing log file 
			cat $log | grep "Action" | cut -f 7 -d " " > .tmpMore
			paste .tmp .tmpMore > .res
			
			# Analyzing (corrected) log 
			match=`head -n 1 .res | awk '{print $1"_"$2"_"$3}'`
			cat .res  |  awk -v S=$match -f stdev3.awk > $resFile
			echo "[PERF] Results correctly written on file <<$resFile>>"
			#rm .tmp .tmpMore 

		else
			echo "[PERF] No file <<$log>> created, check for ERRORS!"
		fi
		;;



	*)	
		;;
esac 

# Cleanup
if [ $# -eq $totParam -a $expType -ne 9 ]
then
	echo "[PERF] Resetting network parameters (after experiment)"
	./network.sh 2
fi

# Kill the server
killServer

# Kill mboxes
killMbox
