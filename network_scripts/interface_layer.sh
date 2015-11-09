brctl show | awk '{if(NR>1)print}' | awk '{print $1, $4}'
