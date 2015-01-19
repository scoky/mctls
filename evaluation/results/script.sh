#!/bin/bash 

# variables
count=1
paper="results"
figFolder="./fig"

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
evince $paper".pdf"
