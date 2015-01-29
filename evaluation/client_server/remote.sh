#!/bin/bash 

# Function to print script usage
usage(){
    echo -e "Usage: $0 opt run [plotCommand]"
    echo -e "opt    = test to be run "
	echo -e "\t(0) Test number of connections per second concurrently on machines from file <<machines>>"
    echo -e "run    = {(1) run test and collect results ; (0) colect results only}"
    echo -e "debug  = {(1) debug only (print command no run); (0) run normally}"
	echo -e "resFolder    = folder where to store results (../results ; ../results/tmp ; ../results/final)"
    echo -e "-------------------------------OPTIONAL---------------------------------------------------"
	echo -e "[plotCommand = {matlab, myplot, ...} add your own to the script (default is no plotting)]"
	exit 0 
}
	
# Set of checks for correctness
[[ $# -lt 4 ]] && usage

# Parameters
opt=$1                      # user choice for experiment
RUN_EXP=$2                  # run experiment or not 
debug=$3                    # run experiment or not 
resFolder=$4                # results folder
plotCommand="none"          # user selection for plotting 
key="amazon.pem"            # amazon key 
machineFile="machines"
remoteFolder="./secure_proxy_protocol/evaluation/client_server"
localFolder="./WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/evaluation/client_server"
protoList[1]="ssl"          # array for protocol types currently supported
protoList[2]="fwd"
protoList[3]="spp"
protoList[4]="pln"
parallel=1                  # flag used for plotting

# read type of plot to do 
if [ $# -eq 5 ]
then 
	plotCommand=$5
fi

# derive proto size 
proto_count=${#protoList[@]}

# no run if u only want to plot 
if [ $RUN_EXP -eq 1 ] 
then
# switch on user selection 
	case $opt in 
	0)
    	echo "[REMOTE] Test number of connections per second on multiple machines (in parallel)"
		machines=0
		if [ -f .active ] 
		then 
			rm .active
		fi
		for line in `cat $machineFile`
		do
			addr=`echo $line | cut -f 2 -d "@" | cut -f 1 -d ":"`
			port=`echo $line | cut -f 2 -d "@" | cut -f 2 -d ":"`
			user=`echo $line | cut -f 1 -d "@"`
			log="log_master_"$addr
			if [ $addr == "localhost" ] 
			then 
				comm="cd $localFolder; ./master.sh 7 0 1 $resFolder"
			else
				comm="cd $remoteFolder; ./master.sh 7 0 1 $resFolder"
			fi

			echo "$addr 1" >> .active
			if [ -f $log ] 
			then 
				rm $log 
			fi
			echo "[REMOTE] Started script at machine $addr (user=$user ; port=$port)"
			if [ $addr == "tid.system-ns.net" -o $addr == "localhost" ]
			then  
				if [ $debug -eq 1 ] 
				then
					echo "ssh -o StrictHostKeyChecking=no -p $port $user@$addr $comm >> $log 2>&1 &"
				else
					ssh -o StrictHostKeyChecking=no -p $port $user@$addr $comm >> $log 2>&1 &
				fi
			else 
				if [ $debug -eq 1 ] 
				then
					echo "ssh -o StrictHostKeyChecking=no -p $port -i $key $user@$addr $comm >> $log 2>&1 &"
				else
					ssh -o StrictHostKeyChecking=no -p $port -i $key $user@$addr $comm >> $log 2>&1 &
				fi
			fi
			let "machines++"
		done

		# if debugging just stop here
		if [ $debug -eq 1 ] 
		then 
			exit 0 
		fi

		# check that experiment is completed everywhere 
		sleep 5 
		running=`ps aux | grep ssh  | grep "master.sh 7" | wc -l`
		while [ $running -gt 0 ] 
		do 
			running=`ps aux | grep ssh  | grep "master.sh 7" | wc -l`
			echo "[REMOTE] Still $running machines are active"
			sleep 10 
		done
		;;
	esac
fi

# Fetch results 
f=`echo $resFolder | awk 'BEGIN{FS="/"}{print $2"/"$3}'`
rf="./secure_proxy_protocol/evaluation/$f/"
lf="$HOME/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/evaluation/$f/"
for line in `cat $machineFile`
do
	addr=`echo $line | cut -f 2 -d "@" | cut -f 1 -d ":"`
	port=`echo $line | cut -f 2 -d "@" | cut -f 2 -d ":"`
	user=`echo $line | cut -f 1 -d "@"`
	for ((i=1; i<=proto_count; i++))
	do
		proto=${protoList[$i]}
		suff=$proto"_connections_slice"
		if [ $addr == "localhost" ] 
		then 
			file1=$lf"res_"$suff"_client"
			file2=$lf"res_"$suff"_mbox"
			file3=$lf"res_"$suff"_server"
		else
			file1=$rf"res_"$suff"_client"
			file2=$rf"res_"$suff"_mbox"
			file3=$rf"res_"$suff"_server"
		fi
		targetFile1=$resFolder"/res_"$proto"_connections_slice_client_"$addr
		targetFile2=$resFolder"/res_"$proto"_connections_slice_mbox_"$addr
		targetFile3=$resFolder"/res_"$proto"_connections_slice_server_"$addr
		echo "[REMOTE] Collecting results from machine <<$addr>>"
		if [ $addr == "tid.system-ns.net" -o $addr == "localhost" ]
		then 
			scp -P $port  $user@$addr:$file1 $targetFile1
			scp -P $port  $user@$addr:$file2 $targetFile2
			scp -P $port  $user@$addr:$file3 $targetFile3
			if [ $addr == "localhost" ] 
			then 		
				rm $file1
				rm $file2
				rm $file3
			fi
		else 
			scp -P $port  -i $key $user@$addr:$file1 $targetFile1
			scp -P $port  -i $key $user@$addr:$file2 $targetFile2
			scp -P $port  -i $key $user@$addr:$file3 $targetFile3
		fi
	done
done

# Plotting results 
# TO DO 
if [ $plotCommand == "matlab" ] 
then 
	echo "[MASTER] Plotting results (option $opt)"
	echo "[MATLAB] Running MATLAB...(it can take some time first time)"
	matlab -nodisplay -nosplash -r "cd $resFolder; plotSigcomm(7, 0, 1); quit"

	# Generating summary report 
	cd ../results 
	../results/script.sh 
	cd - 
else 
	echo "[MASTER] No plotting requested or plotting type <<$plotCommand>> not supported"
fi
