#!/bin/bash 

# Function to print script usage
usage(){
    echo -e "Usage: $0 opt remote [plotCommand]"
    echo -e "opt = {(0) (1) (2) (3) (4) (5) (6) (7) (8)}"
    echo -e "\t(0) Pull new code and compile"
	echo -e "\t(1) Handshake duration (not used)" 
	echo -e "\t(2) Time to first byte f(no. slices)"
	echo -e "\t(3) Time to first byte f(delay)"
	echo -e "\t(4) Time to byte as a function of the number of proxies"
	echo -e "\t(5) Download time as a function of the file size"
	echo -e "\t(6) Download time in browser-like mode -- CDF"
	echo -e "\t(7) Number of connections per second"
	echo -e "\t(8) Byte overhead -- X axis is a few discrete scenarios"
	echo -e "remote = {(0) local experiments (1) Amazon experiments}"
    echo -e "[plotCommand = {matlab, myplot, ...} add your own to the script (default is no plotting)]"
Folder="../results"    exit 0
}
	
# Function to print script usage
tcpTrick(){
	if [ $proto == "spp_mod" ] 
	then 
		rwnd=10
		cwnd=10
		echo "Changing initrwnd to $rwnd and initcwnd to $cwnd"
		sudo ip route change 127.0.0.1 dev lo  proto static initrwnd $rwnd initcwnd $cwnd
		ip route show 
	fi
}

# Set of checks for correctness
[[ $# -lt 2 ]] && usage

# Static parameters
resFolder="../results"    # result folder 
R=50                      # number of repetitions
S_max=16                  # max number of slices 
rate=1                    # common rate
maxRate=8                 # max rate with no traffic
delay=20                  # delay 
iface="lo"                # interface
log="log_script"          # log file 
logCompile="log_compile"  # log file 
opt=$1                    # user choice for experiment
remote=$2                 # user choice, local or Amazon exp
plotCommand="none"        # Usere selection for plotting 
protoList[1]="ssl"        # array for protocol types currently supported
protoList[2]="fwd"
protoList[3]="spp"
#protoList[4]="pln""     
key="amazon.pem"           # amazon key 
user="ubuntu"              # amazon user 

# folder for compilations
remoteFolder="/home/$user/secure_proxy_protocol" 
localFolder=$HOME"WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol"

# derive proto size 
proto_count=${#protoList[@]}

# read user plot input if provided
if [[ $# -eq 3 ]]
then 
	plotCommand=$3
fi

#cleanup 
if [ -f $log ]
then 
	rm -v $log 
fi

# check key exhists (for remote exp)
if [ $remote -eq 1 ] 
then 
	if [ ! -f $key ] 
	then 
		echo "Amazon ssh key is missing (<<$key>>)"
		exit 0 
	fi
fi
#echo "TCP INIT CWND"
#cat /usr/src/linux-headers-3.13.0-39-generic/include/net/tcp.h | grep -A 2 initcwnd
#echo "TCP INIT RWND"
#cat /usr/src/linux-headers-3.13.0-39-generic/include/net/tcp.h | grep -A 2 initrwnd
	
# no run if u only want to plot 
NORUN=0
if [ $NORUN -eq 0 -o $opt -eq 0 ]
then
# switch on user selection 
	case $opt in 
	0)
		echo "[MASTER] Pull code (git) and recompile"
		count=0
		if [ $remote -eq 0 ] 
		then
			cd $localFolder
			git pull
			make
			sudo make install
			cd evaluation/client_server
			make clean
			make
			cd - 
		else
			for i in `cat "./proxyList_amazon"`
			do
				if [ $count -gt 0 ] 
				then 
					addr=`echo $i | cut -f 1 -d ":"`
					comm="cd $remoteFolder; git pull; make; sudo make install; cd evaluation/client_server; make clean; make"
					command="script -q -c '"$comm"'"         # Make typescript version of the command (solve SUDO problem via SSH)
					echo "[MASTER] Working on machine $addr"
		            ssh -o StrictHostKeyChecking=no -i $key $user@$addr "$command" >> $logCompile 2>&1 &
					#echo "ssh -o StrictHostKeyChecking=no -i $key $user@$serverAdr "$command" >> $logCompile 2>&1 &"
				fi 
				let "count++"
			done
		fi
	
		# check that compilation is done and ok 	
		if [ $remote -eq 0 ] 
		then 
			currTime=`date | awk '{print $2"_"$3"_"$4;}'`
			p="/usr/local/ssl/lib"
			echo "[MASTER] Checking for library at location <<$p>>"
			echo "[MASTER] Current time is $currTime."
			echo "[MASTER] Libraries were last compiled:"
			ls -lrth  $p | grep lib | awk '{print "\t" $NF ": "$6"_"$7"_"$8}'
		else
			active=`ps aux | grep ssh | grep amazon | grep script | wc -l`
			while [ $active -gt 0 ] 
			do 
				echo "[MASTER] Still $active compilation running remotely"
				active=`ps aux | grep ssh | grep amazon | grep script | wc -l`
				sleep 10
			done
			count=0
			for i in `cat "./proxyList_amazon"`
			do
				if [ $count -gt 0 ] 
				then 
					addr=`echo $i | cut -f 1 -d ":"`
					command="cd $remoteFolder; cd evaluation/client_server; ./checkLibrary.sh"
		            ssh -o StrictHostKeyChecking=no -i $key $user@$addr "$command"
				fi
				let "count++"
			done
		fi
		
		# all good, just exit 
		echo "[MASTER] Compilation of last version completed"
		exit 0
		;;
	1) 
		echo "[MASTER] Option $opt currently not supported"
		exit 0
		;;
	2)
		echo "[MASTER] Analysis of first time to byte as a function of number of slices (check <<$log>> for experiment progress)"
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			echo -e "\t[MASTER] Working on protocol $proto (Running <<$R>> tests per configuration)"
			if [ $remote -eq 0 ]
			then
				./perf_script.sh $S_max $R $proto $opt $remote $rate $maxRate $delay $iface >> $log
			else
				./perf_script.sh $S_max $R $proto $opt $remote >> $log
				#echo "./perf_script.sh $S_max $R $proto $opt $remote >> $log"
			fi
		done
			;;

	3) 
		echo "[MASTER] Analysis of first time to byte as a function of latency"
		S_max=3
		for ((i=1; i<=proto_count; i++))
		do
			proto=${proto[$i]}
			echo -e "\t[MASTER] Working on protocol $proto ..."
			./perf_script.sh $S_max $R $proto $opt $remote $rate $maxRate $delay $iface >> $log
		done
		;;

	4) 
		echo "[MASTER] Analysis of first time to byte as a function of the number of proxies"
		S_max=3
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			echo -e "\t[MASTER] Working on protocol $proto ..."
			
			# deal with SPP_MOD
			tcpTrick

			# run analysis
			./perf_script.sh $S_max $R $proto $opt $remote $rate $maxRate $delay $iface >> $log
		done
		;;
	
	5) 
		echo "[MASTER] Analysis of download time as a function of the file size"
		echo "!!![MASTER] Increasing transfer rate to 20Mbps and lowering repetitions to just 10 (for testing)!!!"
		#----------------
		rate=10
		maxRate=10
		R=10
		#----------------
		S_max=3
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			echo -e "\t[MASTER] Working on protocol $proto ..."
			
			# deal with SPP_MOD
			tcpTrick
			
			# run analysis
			#echo "./perf_script.sh $S_max $R $proto $opt $rate $maxRate $delay $iface >> $log"
			./perf_script.sh $S_max $R $proto $opt $remote $rate $maxRate $delay $iface >> $log
		done
		;;
	
	6) 
		echo "[MASTER] Analysis of download time in browser-like mode"
		echo "!!![MASTER] Using only 10 repetitions (for testing)!!!"
		#----------------
		R=10
		#----------------
		S_max=3
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			echo -e "\t[MASTER] Working on protocol $proto ..."
			
			# deal with SPP_MOD
			tcpTrick
			
			# run analysis
			#echo "./perf_script.sh $S_max $R $proto $opt $rate $maxRate $delay $iface >> $log"
			./perf_script.sh $S_max $R $proto $opt $remote $rate $maxRate $delay $iface >> $log
		done
		;;
	
	7) 
		echo "[MASTER] Analysis of number of connections per second"
		R=5
		S_max=16
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			echo -e "\t[MASTER] Working on protocol $proto (10 second per parameter value and repetition)"
			#echo "./perf_script.sh $S_max $R $proto $opt $remote $rate $maxRate $delay $iface >> $log"
			./perf_script.sh $S_max $R $proto $opt $remote $rate $maxRate $delay $iface >> $log
		done
		;;
		

	8) 
		echo "[MASTER] Byte overhead -- X axis is a few discrete scenarios"
		echo "[MASTER] NOTE: This test ignores network parameters"
		R=1  # byte overhead shouldn't vary
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			echo -e "\t[MASTER] Working on protocol $proto ..."
			
			# deal with SPP_MOD
			tcpTrick
			
			# run analysis
			# TODO: use local/Amazon flag here once supported (instead of 0)
			./perf_script.sh $S_max $R $proto $opt 0 >> $log
		done
		;;

	esac
fi

# Plotting results 
if [ $plotCommand == "matlab" ] 
then 
	echo "[MASTER] Plotting results (option $opt)"
	echo "[MATLAB] Running MATLAB...(it can take some time first time)"
	matlab -nodisplay -nosplash -r "cd $resFolder; plotSigcomm($opt, $remote); quit"

	# Generating summary report 
	cd ../results 
	../results/script.sh 
	cd - 
elif [ $plotCommand == "myplot" ]
then
	echo "[MASTER] Plotting results (option $opt)"
	cd ../results
	./plot_byte_overhead.py
	cd -
else 
	echo "[MASTER] No plotting requested or plotting type <<$plotCommand>> not supported"
fi
