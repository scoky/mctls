#!/bin/bash 
# Collection of analysis of experiments being ran 

log="logSSL"

# Time analysis 
cat $log | awk '{if ($1 == "New") {split($4, tmp, "#"); split(tmp[2], str, ":"); key = str[1];} if ($1 == key){print $0;}}'

# Print series of events 
cat $log | awk 'BEGIN{state = 1; }{if ($2 == state) {print $0; state = state +1;}}'

