#!/bin/bash

sql2csv="./sqlite3_to_csv.py"

# look on https://wigle.net/account for your API Name and API Token
APIKEY="APIName:APIToken"

usage() {
	echo "Upload logged ssids to wigle.net"
	echo "$0 [-h|--help] BEACON.DB|BEACON.CSV"
}

upload() {
	curl -s -H 'Accept:application/json' -u $APIKEY --basic -F file=@${1} -F donate=false https://api.wigle.net/api/v2/file/upload|jq '.'
}

if ! [ -f "$sql2csv" ] ;then
	echo "Error: sqlite3_to_csv.py script has not been found" >&2
	exit 1
fi

if [ $# -eq 0 ] || [ $1 == "-h" ] || [ $1 == "--help" ] ;then
	usage
	exit 0
fi

if [ $APIKEY == "APIName:APIToken" ] ;then
	echo "You need to modify the script to add your APIKEY" >&2
	exit 1
fi

if [ $# -ge 1 ] ;then
	for f in $@; do
		if [[ "${f##*.}" == "db" ]] ;then
			wf=${f%%.db}.csv
			echo ":: Converting $f to $wf"
			$sql2csv -i $f -o "$wf"
		else
			wf=$f
		fi
		# double check that the header is there
		if head -n 1 $wf|grep -q 'WigleWifi-1.6,appRelease' ; then
			if grep -q WIFI $wf &>/dev/null; then
				echo ":: Uploading... $wf"
				upload "$wf"
			else
				echo ":: skipping empty file $wf" >&2
			fi
		else
			echo ":: skipping $wf because of missing WigleWifi header" >&2
		fi
	done
fi
