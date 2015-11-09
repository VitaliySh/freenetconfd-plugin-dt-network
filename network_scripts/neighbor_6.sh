ip -6 neighbor show dev ${1} | awk '/lladdr/ {print $1, $3, $5}'
