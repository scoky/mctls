#!/bin/bash 
# A simple script to enable experiments with s_client ---> s_server

# Documentation to refer to
# SERVER -- https://www.openssl.org/docs/apps/s_server.html
# CLIENT -- https://www.openssl.org/docs/apps/s_client.html

# set of variables
host="localhost"		# host where server is running
port=4433				# port to be used
cert="mycert.pem"		# server certificate
path=$HOME"/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/apps"	# path
confFile="openssl.cnf"	# ssl configuration file
time=1					# sleeping time for GET stdin for openssl (longer for remote sites, i.e., real settings)
crawl="crawl"			# crawl folder for content to serve
list=$crawl"/list"		# list of websites
logServer="serverLog"	# log file for server (debugging)

# cleaning
if [ -f $logServer ] 
then 
	rm $logServer
fi

# test (local) OpenSSL configuration 
if [ ! -d "./ssl" ] 
then 
	mkdir -v ./ssl
	cp -v $path"/"openssl.cnf ./ssl
else
	if [ ! -f "./ssl/openssl.cnf" ] 
	then 
		cp -v $path"/"openssl.cnf ./ssl
	fi
fi

# generate server certificate if needed 
if [ ! -f $cert ] 
then 
	echo "Generating server certificate..."
	$path"/openssl" req  -x509 -nodes -days 365 -newkey rsa:1024 -keyout $cert -out $cert
	# TO DO -- fix details here 
fi 

# server setup (using default port 4433)
PID=`ps aux | grep s_server | grep -v grep | cut -f 2 -d " "`
if [ ! -z "$PID" ]
then
	echo "Server already running! Killing..."
	kill -9 $pid
fi
echo "Starting server..."
$path"/openssl" s_server -cert mycert.pem -WWW -msg >> $logServer  2>&1 &
#echo "$path"openssl" s_server -cert mycert.pem -WWW -msg >> $logServer  2>&1 &"

# sleeping one second just to allow for setup 
sleep 1 

# client setup measuring time 
for i in `cat $list`
do 
	echo "Testing server with content $i"
	(echo "GET "/"$crawl/$i".html" HTTP/1.1"; sleep $time) | $path"/openssl" s_client -connect $host:$port >> $crawl"/"log_$i 2>&1
	echo "(echo "GET "/"$crawl/$i".html" HTTP/1.1"; sleep $time) | $path"/openssl" s_client -connect $host:$port >> $crawl"/"log_$i 2>&1"
done

# task completed
echo "All done!"
