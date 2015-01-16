#!/bin/bash 

# Matlab stuff 
echo "Running MATLAB..."
matlab -nodisplay -nosplash -r "plotHandshake; quit"

# Latex stuff 
#echo "Compiling TEX..."
#cd ./latex
#TEX-compile.sh main.tex 1 0 
#rm main.blg main.bbl main.log main.dvi main.aux main.ps
#cd ..

