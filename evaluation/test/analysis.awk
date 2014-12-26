{
	if ($1 == "New") {
		split($4, tmp, "#")
		split(tmp[2], str, ":")
		key = sprintf("%d", str[1]);
	} 
	if ($1 == key){
		if ($NF == "application_data") {
			tH = tC;
		} 
		if($2 == 1){
			tS = $3
			tC = $3
		} else {
			tC = $3;
		}
		print $0;
	}
}
END{
	tHandshake = (tH - tS)*1000
	tPassed = (tC - tS)*1000
	tTransfer = (tPassed - tHandshake)
	print "#---------------------------#"
	print "Handshake: " tHandshake "ms"
	print "Transfer: " tTransfer "ms"
	print "Total: " tPassed "ms"
}
