#!/bin/bash
echo "Cleaning"
rm -v privkey.pem ca.pem server.req file.srl client.key client.req server.key

echo "Generate a CA"
openssl req -out ca.pem -new -x509  
cat privkey.pem ca.pem > root.pm 

echo "----"

echo "Generate server certificate/key pair -- no password required"
openssl genrsa -out server.key 1024
openssl req -key server.key -new -out server.req
echo "00" > file.srl 
openssl x509 -req -in server.req -CA ca.pem -CAkey privkey.pem -CAserial file.srl -out server.pem
cat server.key server.pem > temp 
mv temp server.pem 

echo "----"

echo "Generate client certificate/key pair"
en=0
if [ $en -eq 1 ] 
then 
	openssl genrsa -des3 -out client.key 1024
else
	openssl genrsa -out client.key 1024
fi
openssl req -key client.key -new -out client.req
#echo "00" > file.srl		# does this need to be changed? 
openssl x509 -req -in client.req -CA ca.pem -CAkey privkey.pem -CAserial file.srl -out client.pem
cat client.key client.pem > temp 
mv temp client.pem 

