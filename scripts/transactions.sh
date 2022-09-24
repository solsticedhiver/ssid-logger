#!/bin/bash

# depends: curl, jq

# look on https://wigle.net/account for your API Name and API Token
token="APIName:APIToken"

transactions() {
	curl -s -H 'Accept:application/json' -u $token --basic "https://api.wigle.net/api/v2/file/transactions?pagestart=0&pageend=${1}"|jq '.["results"]|reverse'
}

stats() {
	curl -s -X GET "https://api.wigle.net/api/v2/stats/user" -H "accept: application/json" -u $token --basic |jq '.'
}

usage() {
	echo "Retrieve information about latest transactions uploaded to wigle.net API"
	echo "$0 [-h]  [-c NUMBER | -s]"
	echo "    -c NUMBER, NUMBER of transaction to look for, starting from the last"
	echo "    -s, print stats about your account"
}

STATS=false
COUNT=1
while getopts "hc:s" OPTION; do
    case $OPTION in
    c)
        COUNT=$OPTARG
        ;;
    h)
        usage
	exit 0
        ;;
    s)
        STATS=true
        ;;
    *)
        usage
        exit 1
        ;;
    esac
done
shift $(($OPTIND-1))
if [[ $# -gt 0 ]] ;then
	echo "Warning: ignoring arguments: $@"
fi

if [ "$token" == "APIName:APIToken" ] ;then
	echo "You need to modify the script to add your APIKEY" >&2
	exit 1
fi

if [[ $STATS == "true" ]];then
	stats
else
	transactions $COUNT
fi
