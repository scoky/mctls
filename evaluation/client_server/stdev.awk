BEGIN{
	S = 1
	sum = 0
	count = 0
}
function compute()
{
	sumsq = 0
	avg = sum / count
	for( x = 0; x < count; x++){
		sumsq += ((array[x]-(sum/(count)))**2)
	}
	print S " " avg " " sqrt(sumsq/(count))
}
{
	if($1 == S){
		sum += $2 
		array[count] = $2 
		count = count + 1
	} else {
		compute()
		count = 0
		sum = $2
		delete array 
		array[count] = $2
		S += 1
	}
}
END{
	compute()
}

