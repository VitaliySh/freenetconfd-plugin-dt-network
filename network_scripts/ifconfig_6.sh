ifconfig -a ${1} | awk '/inet6/ {print $2, $4}' | sed 's/\addr://g' | sed 's/\Mask://g'
