#!/bin/bash 

# Function to print script usage
usage(){
    echo -e "Usage: $0 opt remote run resFolder [plotCommand debug tmp]"
    echo -e "opt  = {(0) (1) (2) (3) (4) (5) (6) (7) (8)}"
    echo -e "\t(0) Pull new code and compile"
	echo -e "\t(1) Handshake duration (not used)" 
	echo -e "\t(2) Time to first byte f(no. slices)"
	echo -e "\t(3) Time to first byte f(delay)"
	echo -e "\t(4) Time to byte as a function of the number of proxies"
	echo -e "\t(5) Download time as a function of the file size"
	echo -e "\t(6) Download time in browser-like mode -- CDF"
	echo -e "\t(7) Number of connections per second"
	echo -e "\t(8) Byte overhead -- X axis is a few discrete scenarios"
	echo -e "\t(9) Time to first byte f(scenarios) -- scenarios from file <<scenarios>>, 10 reps"
	echo -e "remote       = {(0) local experiments (1) Amazon experiments}"
	echo -e "run          = {(1) run experiment, (0) no run just plot"
	echo -e "resFolder    = folder where to store results (../results ; ../results/tmp ; ../results/final)"
	echo -e "----------------------------------OPTIONAL-----------------------------------------------"
    echo -e "[plotCommand = {matlab, myplot, none, ...} add your own to the script (default is no plotting)]"
    echo -e "[debug       =  {(0) OFF (1) ON (instead of running just prints commands used)}]"
	exit 0
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
[[ $# -lt 4 ]] && usage

# Parameters
opt=$1                    # user choice for experiment
remote=$2                 # user choice, local or Amazon exp
RUN_EXP=$3                # run experiment or not 
resFolder=$4              # results folder 
matlabFolder="../results" # matlab folder 
R=50                      # number of repetitions
S_max=16                  # max number of slices 
rate=1                    # common rate
maxRate=8                 # max rate with no traffic
delay=20                  # delay 
iface="lo"                # interface
logCompile="log_compile"  # log file 
parallel=0                # parallel experiment (not used here but needed for plotting)
debug=0                   # no debugging by default
plotCommand="none"        # Usere selection for plotting 
key="amazon.pem"          # amazon key 
user="ubuntu"             # amazon user 
#protoList[1]="ssl"       # array for protocol types currently supported
#protoList[2]="fwd"
#protoList[3]="spp"
#protoList[4]="pln"     
#protoList[5]="spp_mod"     
# ---- Nagel OFF for ALL
protoList[1]="ssl_mod"       
#protoList[2]="fwd_mod"
#protoList[3]="spp_mod"
#protoList[4]="pln_mod"     


# folder for compilations
remoteFolder="./secure_proxy_protocol" 
localFolder=$HOME"WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol"

# derive proto size 
proto_count=${#protoList[@]}

# read user plot input if provided
if [[ $# -ge 5 ]]
then 
	plotCommand=$5
fi
# instead of running just print commands
if [ $# -ge 6 ]
then 
	debug=$6                 
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
# Definition for logging purpose 
if [ $remote -eq 1 ] 
then 
	adj="Remote (Amazon)"
else
	adj="Local"
fi

#echo "TCP INIT CWND"
#cat /usr/src/linux-headers-3.13.0-39-generic/include/net/tcp.h | grep -A 2 initcwnd
#echo "TCP INIT RWND"
#cat /usr/src/linux-headers-3.13.0-39-generic/include/net/tcp.h | grep -A 2 initrwnd
	
# no run if u only want to plot 
if [ $RUN_EXP -eq 1 -o $opt -eq 0 ]
then
# switch on user selection 
	case $opt in 
	0)
		machineFile="machines"
		count=0
		echo "[MASTER] Compilation of last version STARTED"
		if [ $remote -eq 0 ] 
		then
			echo "[MASTER] Pull code (git) and recompile at local machine (check your path. Current path is <<$localFolder>>!!!!)"
			cd $localFolder
			git pull
			make
			sudo make install_sw
			cd evaluation/client_server
			make clean
			make
			cd - 
		else
			echo "[MASTER] Pull code (git) and recompile at machine in file <<$machinesFile>>"
			if [ ! -f $machineFile ] 
			then 
				echo "[MASTER] ERROR! File <<$machinesFile>> is missing"
				exit 0 
			fi
			for line in `cat $machineFile`
			do
				comm="cd $remoteFolder; git fetch --all; git reset --hard origin/master; make clean; ./config; make; sudo make install_sw; cd evaluation/client_server; make clean; make"
				command="script -q -c '"$comm"'"         # Make typescript version of the command (solve SUDO problem via SSH)
				addr=`echo $line | cut -f 2 -d "@" | cut -f 1 -d ":"`
				port=`echo $line | cut -f 2 -d "@" | cut -f 2 -d ":"`
				user=`echo $line | cut -f 1 -d "@"`
				echo "[MASTER] Working on machine <<$addr:$port>> (with user <<$user>>)"
				if [ $addr == "localhost" ]
				then
					continue
				fi
				if [ $addr == "tid.system-ns.net" ]
				then
		            ssh -o StrictHostKeyChecking=no -p $port $user@$addr "$command" >> $logCompile 2>&1 &
                else
		            ssh -o StrictHostKeyChecking=no -p $port -i $key $user@$addr "$command" >> $logCompile 2>&1 &
				fi            
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
			active=`ps aux | grep ssh | grep make | grep script | grep -v grep | wc -l`
			while [ $active -gt 0 ] 
			do 
				echo "[MASTER] Still $active compilation running remotely"
				active=`ps aux | grep ssh | grep make | grep script | grep -v grep | wc -l`
				sleep 10
			done
			count=0
			for line in `cat $machineFile`
			do
				command="cd $remoteFolder; cd evaluation/client_server; ./checkLibrary.sh"
				addr=`echo $line | cut -f 2 -d "@" | cut -f 1 -d ":"`
				port=`echo $line | cut -f 2 -d "@" | cut -f 2 -d ":"`
				user=`echo $line | cut -f 1 -d "@"`
				echo "[MASTER] Checking machine <<$addr:$port>> (with user <<$user>>)"
				if [ $addr == "localhost" ]
				then
					continue
				fi
				if [ $addr == "tid.system-ns.net" ]
				then
		            ssh -o StrictHostKeyChecking=no -p $port $user@$addr "$command" 
                else
		            ssh -o StrictHostKeyChecking=no -p $port -i $key $user@$addr "$command"
				fi 
			done
		fi
		
		# all good, just exit 
		echo "[MASTER] Compilation of last version COMPLETED"
		exit 0
		;;
	1) 
		echo "[MASTER] Option $opt currently not supported"
		exit 0
		;;
	2)
		echo "[MASTER] $adj analysis of first time to byte as a function of number of slices (check <<$log>> for experiment progress)"
		R=10
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			log="log_script_"$proto 
			#cleanup 
			if [ -f $log ]
			then 
				rm -v $log 
			fi
			echo -e "\t[MASTER] Working on protocol $proto (Running <<$R>> tests per configuration)"
			if [ $remote -eq 0 ]
			then
				if [ $debug -eq 1 ] 
				then
					echo "./perf_script.sh $S_max $R $proto $opt $resFolder $remote $rate $maxRate $delay $iface >> $log"
				else
					./perf_script.sh $S_max $R $proto $opt $remote $resFolder $rate $maxRate $delay $iface >> $log 2>/dev/null
				fi
			else
				if [ $debug -eq 1 ] 
				then
					echo "./perf_script.sh $S_max $R $proto $opt $remote $resFolder >> $log"
				else
					./perf_script.sh $S_max $R $proto $opt $remote $resFolder >> $log 2>/dev/null
				fi
			fi
		done
			;;

	3) 
		echo "[MASTER] $adj analysis of first time to byte as a function of latency"
		S_max=4
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			log="log_script_"$proto 
			if [ -f $log ]
			then 
				rm -v $log 
			fi
			echo -e "\t[MASTER] Working on protocol $proto ..."

			# run analysis
			if [ $debug -eq 1 ] 
			then
				echo "./perf_script.sh $S_max $R $proto $opt $remote $resFolder $rate $maxRate $delay $iface >> $log 2>/dev/null"
			else
				./perf_script.sh $S_max $R $proto $opt $remote $resFolder $rate $maxRate $delay $iface >> $log 2>/dev/null
			fi
		done
		;;

	4) 
		echo "[MASTER] $adj analysis of first time to byte as a function of the number of proxies"
		S_max=4
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			log="log_script_"$proto 
			if [ -f $log ]
			then 
				rm -v $log 
			fi
			echo -e "\t[MASTER] Working on protocol $proto ..."
			
			# run analysis
			if [ $debug -eq 1 ] 
			then
				echo "./perf_script.sh $S_max $R $proto $opt $remote $resFolder $rate $maxRate $delay $iface >> $log 2>/dev/null"
			else
				./perf_script.sh $S_max $R $proto $opt $remote $resFolder $rate $maxRate $delay $iface >> $log 2>/dev/null
			fi
		done
		;;
	
	5) 
		echo "[MASTER] $adj analysis of download time as a function of the file size"
		echo "!!![MASTER] Increasing transfer rate to 20Mbps and lowering repetitions to just 10 (for testing)!!!"
		#----------------
		rate=10
		maxRate=10
		R=10
		#----------------
		S_max=4
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			log="log_script_"$proto 
			if [ -f $log ]
			then 
				rm -v $log 
			fi
			echo -e "\t[MASTER] Working on protocol $proto ..."
			
			# deal with SPP_MOD
			tcpTrick
			
			# run analysis
			if [ $debug -eq 1 ] 
			then
				echo "./perf_script.sh $S_max $R $proto $opt $remote $resFolder $rate $maxRate $delay $iface"
			else
				./perf_script.sh $S_max $R $proto $opt $remote $resFolder $rate $maxRate $delay $iface >> $log 2>/dev/null
			fi
		done
		;;
	
	6) 
		echo "[MASTER] $adj analysis of page loading time in browser-like mode"
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			log="log_script_"$proto 
			if [ -f $log ]
			then 
				rm -v $log 
			fi
			echo -e "\t[MASTER] Working on protocol $proto ..."
			
			# run analysis
			if [ $remote -eq 0 ]
			then
				if [ $debug -eq 1 ] 
				then
					echo "./perf_script.sh 1 1 $proto $opt $remote $resFolder $rate $maxRate $delay $iface >> $log 2>/dev/null"
				else
					./perf_script.sh 1 1 $proto $opt $remote $resFolder $rate $maxRate $delay $iface >> $log 2>/dev/null
				fi
			else
				if [ $debug -eq 1 ] 
				then
					echo "./perf_script.sh 1 1 $proto $opt $remote $resFolder >> $log 2>/dev/null"
				else
					./perf_script.sh 1 1 $proto $opt $remote $resFolder >> $log 2>/dev/null
				fi

			fi
		done
		;;
	
	7) 
		echo "[MASTER] $adj analysis of number of connections per second"
		R=5
		S_max=16
		str="l($S_max)/l(2)"
		X=`echo $str | bc -l  | cut -f 1 -d "."`
		let "estTime = (R * X * 30) / 60)"
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			log="log_script_"$proto 
			if [ -f $log ]
			then 
				rm -v $log 
			fi
			echo -e "\t[MASTER] Working on protocol $proto (30 second per parameter value and repetition. Est time $estTime minutes)"
			if [ $debug -eq 1 ] 
			then
				echo "./perf_script.sh $S_max $R $proto $opt $remote $resFolder $rate $maxRate $delay $iface >> $log"
			else
				./perf_script.sh $S_max $R $proto $opt $remote $resFolder $rate $maxRate $delay $iface >> $log 2>/dev/null
			fi
		done
		;;
		

	8) 
		echo "[MASTER] $adj analysis of byte overhead -- X axis is a few discrete scenarios"
		echo "[MASTER] NOTE: This test ignores network parameters"
		R=1  # byte overhead shouldn't vary
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			log="log_script_"$proto 
			if [ -f $log ]
			then 
				rm -v $log 
			fi
			echo -e "\t[MASTER] Working on protocol $proto ..."
			
			# run analysis
			# TODO: use local/Amazon flag here once supported (instead of 0)
			if [ $debug -eq 1 ] 
			then
				echo "./perf_script.sh $S_max $R $proto $opt 0 $resFolder >> $log 2>/dev/null"
			else
				./perf_script.sh $S_max $R $proto $opt 0 $resFolder >> $log 2>/dev/null
			fi
		done
		;;
	
	9)
		echo "[MASTER] $adj analysis of time to first byte as function of scenarios from file <<scenarios>>"
		echo "[MASTER] NOTE: This test ignores network parameters"
		for ((i=1; i<=proto_count; i++))
		do
			proto=${protoList[$i]}
			log="log_script_"$proto 
			if [ -f $log ]
			then 
				rm -v $log 
			fi
			echo -e "\t[MASTER] Working on protocol $proto ..."
			
			if [ $debug -eq 1 ] 
			then
				echo "./perf_script.sh 0 0 $proto $opt 0 $resFolder"
			else
				./perf_script.sh 0 0 $proto $opt 0 $resFolder >> $log 2>/dev/null
			fi
		done
		;;

	10) 
		echo "[MASTER] Collecting results"
		m="tid.system-ns.net"
		us_m="research"
		echo "collect results from machine <<$m>> from final folder"
		cd ../evaluation/results/final
		rsync -avzh -e 'ssh -p 22222' --progress $us_m@$m:./secure_proxy_protocol/evaluation/results/final/* ./
		cd - 
	esac
fi

# Plotting results 
if [ $plotCommand == "matlab" ] 
then 
	echo "[MASTER] Plotting results (option $opt)"
	echo "[MATLAB] Running MATLAB...(it takes some time at first launch)"

	if [ $opt -eq 7 ] 
	then 
		matlab -nodisplay -nosplash -r "cd $matlabFolder; plotSigcomm($opt, $remote, $parallel, 'client', $resFolder, ''); plotSigcomm($opt, $remote, $parallel, 'mbox', $resFolder, ''); plotSigcomm($opt, $remote, $parallel, 'server', $resFolder, '');quit"
	else 
		echo "plotSigcomm($opt, $remote, $parallel, 'none', $resFolder, '')"
		matlab -nodisplay -nosplash -r "cd $matlabFolder; plotSigcomm($opt, $remote, $parallel, 'none', $resFolder, ''); quit"
	fi

	# Generating summary report 
	cd ../results 
	../results/script.sh 
	cd - 
elif [ $plotCommand == "myplot" ]
then
	echo "[MASTER] Plotting results (option $opt)"
	cd ../results
	./plot.py $opt
	cd -
else 
	echo "[MASTER] No plotting requested or plotting type <<$plotCommand>> not supported"
fi
