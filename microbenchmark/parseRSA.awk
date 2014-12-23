function printResRSA(){
	for (i=0; i < counter; i++){
		print oldKey " & " bit[i]  " & " signT[i] " & " verifyT[i] " & " sign[i] " & " verify[i] " \\\\ \\hline"
	}
}

function printRes(){
	str = oldKey
	for (i=0; i < counter; i++){
		str = str " & " res[i]
	}
	str = str " \\\\ \\hline"
	print str
}

BEGIN{
	oldKey = "START"
	print "\\begin{table}[htb]"
	print "\\centering"
	print "\\begin{tabular}{|c||c|c|c|c|c|}"
	print "\\hline"
	if (RSA == 1){
		print "\\textbf{protocol} & \\textbf{16} & \\textbf{64} & \\textbf{256} & \\textbf{1024} & \\textbf{8192} \\\\ \\hline"
	} else {
		print "\\textbf{protocol} & \\textbf{bits} & \\textbf{sign} & \\textbf{verify} & \\textbf{sign/} & \\textbf{verify/s} \\\\ \\hline"
	}
	print "\\hline"
}
{
	# update key value 
	if ($1 == "rsa" || $1 == "dsa"){
		key = $1
	} else {
		key=$2
	}

	# print results if needed
	if (key != oldKey){
		if (oldKey != "START"){
			if (oldKey == "rsa" || key == "dsa"){
				printResRSA()
				delete bit 
				delete signT
				delete verifyT 
				delete sign 
				delete verify 
			} else {
				printRes()
				delete res
			}
		}

		# update  
		oldKey = key
		counter = 0 
	}
	
	# main loop
	#print "DEBUG " key "---" counter "----" $9 
	if (key == "rsa" || key == "dsa"){
		#rsa  512 bits 0.000056s 0.000005s  17779.4 219220.5
		#print $0
		bit[counter] = $2
		signT[counter] = $4
		verifyT[counter] = $5
		sign[counter] = $6
		verify[counter] = $7
	}
	else{
		res[counter] = $9
	}

	# increase counter
	counter = counter + 1
}

# print last report + finish up table
END{
	if (oldKey == "rsa" || key == "dsa"){
		printResRSA()
	}else{
		printRes()
	}
	print "\\end{tabular}"
	
	if (oldKey == "rsa" || key == "dsa"){
		print "\\caption{Performance results from speed.c with classic \\ssl ; RSA/DSA.}"
		print "\\label{tab:perf_RSA}"
	} else {
		print "\\caption{Performance results from speed.c with classic \\ssl.}"
		print "\\label{tab:perf}"
	}
	print "\\end{table}"
}
	
