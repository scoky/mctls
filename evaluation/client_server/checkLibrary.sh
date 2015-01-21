#!/bin/bash 
currTime=`date | awk '{print $2"_"$3"_"$4;}'`
p="/usr/local/ssl/lib"


echo "Current time is $currTime."
echo "Library were last compiled:"
ls -lrth  $p | grep lib | awk '{print "\t" $NF ": "$6"_"$7"_"$8}'
