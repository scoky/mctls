#!/bin/bash 

# Function to print script usage
usage(){
    echo -e "Usage: $0 opt"
    echo -e "opt = {1) handshake (not used), 2) time to first byte f(no. slices) - 3) time to first byte f(delay) - 4)....}"
    exit 0
}

# Set of checks for correctness
[[ $# -lt 1 ]] && usage

# save user input
opt=$1

# Matlab stuff 
echo "Running MATLAB..."
matlab -nodisplay -nosplash -r "plotSigcomm($opt); quit"
