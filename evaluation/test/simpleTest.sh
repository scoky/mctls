#!/bin/bash 
# A simple script to enable experiments with s_client ---> s_server

# Documentation to refer to
# SERVER -- https://www.openssl.org/docs/apps/s_server.html
# CLIENT -- https://www.openssl.org/docs/apps/s_client.html

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

# generate server certificate if needed 
if [ ! -f $cert ] 
then 
	echo "Generating server certificate..."
	$path"/openssl" req  -x509 -nodes -days 365 -newkey rsa:1024 -keyout $cert -out $cert
	# TO DO -- fix details here 
fi 

# server setup (using default port 4433)
PID=`ps aux | grep s_server | grep -v grep | cut -f 2 -d " "`
if [ -z "$PID" ]
then
	echo "Starting server..."
	$path"/openssl" s_server -accept $port -cert $cert -www & 
	# -cert -- indicate certificate to use 
	# -accept port -- indicates TCP port to use, default is 4433
	# -ssl3, -tls1, -no_ssl3, -no_tls1 -- these options disable the use of certain SSL or TLS protocols. 
	# -www -- sends status message back to the client when it connects 
	# -HTTP -- emulates a simple web server. The files loaded are assumed to contain a complete and correct HTTP response 
else
	echo "Server already running!"
fi

# sleeping one second just to allow for setup 
sleep 1 

# client setup measuring time 
echo "Starting client to measure time..."
$path"/openssl" s_time -connect $host:$port -www / -new -ssl3
# -connect host:port -- specifies host and (optional) port to connect to
# -www page -- this specifies the page to GET from the server. A value of '/' gets the index.htm[l] page.
# -new -- performs  timing test using a new session ID for each connection. 
# -reuse -- performs timing test using the same session ID (test for session caching)
# -ssl3 -- ...?
