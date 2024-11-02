#!/bin/bash


BASE="$HOME/src/pwnedpasswords"

SHA1=$(echo -n "$1" | sha1sum | awk '{ print $1 }')
#echo "SHA1=$SHA1"
HEAD=${SHA1:0:5}
#echo "HEAD=$HEAD"
TAIL=${SHA1:5}
#echo "TAIL=$TAIL"
if [ -d "$BASE" ]; then
	#echo "local"
	RES=$(grep -i "$TAIL" "$BASE/${HEAD^^}")
else
	#echo "remote"
	RES=$(curl "https://api.pwnedpasswords.com/range/$HEAD" 2>/dev/null | grep -i "$TAIL")
fi
#echo "$RES"
if [ -n "${RES}" ]; then
	echo "$RES"
fi
