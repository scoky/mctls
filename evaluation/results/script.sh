#!/bin/bash 
# compile the results in a single .pdf  

# variables
count=1
paper="results"
figFolder="./fig"

# For MAC lovers... (to check) 
if [ "$(uname)" == "Darwin" ]
then
	if_mac=1
else
	if_mac=0
fi

# restore beginning of paper
cat base.tex > $paper".tex"

# add figures
for filename in `ls $figFolder| grep eps | grep -v "pdf"`
do 
	echo "\begin{figure}[!htbp]" >> $paper".tex"
	echo "\centering" >> $paper".tex"
	echo "\psfig{figure="$figFolder"/"$filename", width=4.1in}" >> $paper".tex"
	echo "\label{fig:eval_$count}" >> $paper".tex"
	echo "\end{figure}" >> $paper".tex"
	echo -e "" >> $paper".tex"
	let "count++"
done

echo "\end{document}" >> $paper".tex"

# compile 
make $paper

# show 
if [ $if_mac -eq 0 ] 
then 
	evince $paper".pdf" & 
else
	open $paper".pdf" & 
fi
