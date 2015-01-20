#!/bin/bash 

# Function to print script usage
usage(){
    echo -e "Usage: $0 opt"
    echo -e "opt = {1) handshake (not used), 2) time to first byte f(no. slices) - 3) time to first byte f(delay) - 4)....}"
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
[[ $# -lt 1 ]] && usage

# Static parameters
resFolder="../results"    # result folder 
R=5                       # number of repetitions
S_max=16                  # max number of slices 
rate=1                    # common rate
maxRate=8                 # max rate with no traffic
delay=20                  # delay 
iface="lo"                # interface
log="log_script"          # log file 
opt=$1                    # user choice 
protoList[1]="ssl"        # array for protocol types currently supported
protoList[2]="fwd"
protoList[3]="spp"
#protoList[4]="spp_mod"   # here tried running with modified TCP param but with no results

# derive proto size 
proto_count=${#protoList[@]}

#cleanup 
if [ -f $log ]
then 
	rm -v $log 
fi


echo "TCP INIT CWND"
cat /usr/src/linux-headers-3.13.0-39-generic/include/net/tcp.h | grep -A 2 initcwnd
echo "TCP INIT RWND"
cat /usr/src/linux-headers-3.13.0-39-generic/include/net/tcp.h | grep -A 2 initrwnd
	
# switch on user selection 
case $opt in 
	1) 
		echo "[MASTER] Option $opt currently not supported"
		;;
	2)
		echo "[MASTER] Analysis of first time to byte as a function of number of slices (check <<$log>> for experiment progress)"
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			echo -e "\t[MASTER] Working on protocol $proto ..."
			./perf_script.sh $S_max $R $proto $opt $rate $maxRate $delay $iface >> $log
		done
			;;

	3) 
		echo "[MASTER] Analysis of first time to byte as a function of latency"
		S_max=3
		for ((i=1; i<=proto_count; i++))
		do
			proto=${proto[$i]}
			echo -e "\t[MASTER] Working on protocol $proto ..."
			./perf_script.sh $S_max $R $proto $opt $rate $maxRate $delay $iface >> $log
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
			./perf_script.sh $S_max $R $proto $opt $rate $maxRate $delay $iface >> $log
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
			./perf_script.sh $S_max $R $proto $opt $rate $maxRate $delay $iface >> $log
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
			./perf_script.sh $S_max $R $proto $opt $rate $maxRate $delay $iface >> $log
		done
		;;
	
	7) 
		echo "[MASTER] Number of connctions -- Matteo is working on it"
		;;

	8) 
		echo "[MASTER] Byte overhead -- X axis is a few discrete scenarios"
		;;

esac

# Plotting results 
if [ $opt -gt 1 ] 
then 
	echo "[MASTER] Plotting results (option $opt)"
	echo "[MATLAB] Running MATLAB...(it can take some time first time)"
fi
matlab -nodisplay -nosplash -r "cd $resFolder; plotSigcomm($opt); quit"

# Generating summary report 
cd ../results 
./script.sh 
cd - 
