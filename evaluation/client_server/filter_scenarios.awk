BEGIN{
	numSlices = -1
	numMboxes = -1
	fileSize = -1
}
{
	if($1 != numSlices || $2 != numMboxes || $3 != fileSize){
		print $1 " " $2 " " $3 " " $4 " " $5 " " $6 " " $7 " " $8

		numSlices = $1
		numMboxes = $2
		fileSize = $3
	}
}
