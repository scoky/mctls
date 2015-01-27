BEGIN{
	sum = 0
	count = 0
}
function compute()
{
	sumsq = 0
	avg = sum / count
	for( x = 0; x < count; x++){
		sumsq += ((array[x]-(sum/(count)))^2)
	}
	print key " " avg " " sqrt(sumsq/(count))
}
{
	key=$1" "$2" "$3
	if($1 == S){
		sum += $4 
		array[count] = $4 
		count = count + 1
	} else {
		compute()
		count = 0
		sum = $4
		delete array 
		array[count] = $4
		count = count + 1
		S = key
	}
}
END{
	compute()
}

