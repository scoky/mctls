#!/bin/bash 

# Parameters
N_input=1
iface="lo"

# Function to print script usage
usage(){
    echo -e "Usage: $0 opt"
    echo -e "opt = [1=limit speed ; 2=remove rate control ; 3=list configured rules]"
    echo -h "NOTE: you can use <<nload lo>> to visualize traffic"
	exit 0;
}

# Set of checks for correctness
[[ $# -lt $N_input ]] && usage

# User choice
opt=$1

#More check 
if [ $opt -eq 1 ] 
then 
	if [ $# -lt 4 ] 
	then 
		echo "OPT=1 requires 3 more parameters: rate[Mbps] max_rate[Mbps] delay[ms]"
		usage
	else
		rate=$2"Mbps"
		maxRate=$3"Mbps"
		delay=$4"ms"
	fi 
fi

case $opt in 
1)	#Speed and delay control 
	sudo tc qdisc add dev $iface root handle 1: htb default 12
	sudo tc class add dev $iface parent 1:1 classid 1:12 htb rate $rate ceil $maxRate
	sudo tc qdisc add dev $iface parent 1:12 netem delay $delay
	;;

2)	#Remove the rate control/delay
	sudo tc qdisc del dev $iface root
	;;

3)  #Check what is configured on an interface
	sudo tc -s qdisc ls dev $iface
	;;

esac
 
