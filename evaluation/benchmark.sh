#!/bin/bash 

# common variables
path=$HOME"/WorkTelefonica/HTTP-2/sigcomm_evaluation/secure_proxy_protocol/apps"
log="log_speed"
tables="../latex/tables.tex"

#cleaning
if [ -f $log ] 
then 
	rm $log
fi

# RSA and DSA testing 
echo "Testing RSA and DSA..."
$path"/openssl" speed rsa dsa >> $log 2>&1
cat $log | grep rsa | grep bits | awk -f parseRSA.awk > $tables

# Some formatting on tables.tex
echo "" >> $tables
echo "" >> $tables

# Other algo testing 
rm $log
echo "Testing MD4 and SHA1..."
#$path"/openssl" speed md4 sha1 sha256 sha512 >> $log 2>& 1 
$path"/openssl" speed md4 sha1 >> $log 2>&1 
cat $log | grep -v WARNING | awk -f parseRSA.awk >> $tables
