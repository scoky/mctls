#!/bin/bash 

# common variables
host="localhost"
port=4433
cert="mycert.pem"
path=$HOME"/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/apps"
pathSSL=$HOME"/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/ssl"
confFile="openssl.cnf"

# Test (local) OpenSSL configuration 
if [ ! -f $pathSSL"/openssl.cnf" ] 
then 
	echo "Config file openssl.cnf [NOK]"
	cp -v $path"/"openssl.cnf $pathSSL
else
	echo "Config file openssl.cnf [OK]"
fi

# Generate certificate if needed 
if [ ! -f $cert ] 
then 
	echo "Generating server certificate..."
	$path"/openssl" req  -x509 -nodes -days 365 -newkey rsa:1024 -keyout $cert -out $cert
fi 

# server setup (using default port 4433)
PID=`ps aux | grep s_server | grep -v grep | cut -f 2 -d " "`
if [ -z "$PID" ]
then
	echo "Starting server..."
	$path"/openssl" s_server -cert $cert -www & 
else
	echo "Server already running!"
fi

sleep 1 

# client setup measuring time 
echo "Starting client to measure time..."
$path"/openssl" s_time -connect $host:$port -www / -new -ssl3
