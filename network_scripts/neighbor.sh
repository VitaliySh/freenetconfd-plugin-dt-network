ip -4 neighbor show dev ${1} | awk '/lladdr/ {print $1, $3}'
