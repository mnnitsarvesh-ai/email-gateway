#!/bin/sh
# Synthetic benign probe (step 4.6 §9.3). NOT malware. One action: leave two files in the
# runner's scratch: the EICAR anti-virus TEST string (assembled from parts at run time, never
# stored whole in the repository) and a tiny executable shell script. Prints one RESULT line.
a='X5O!P%@AP[4\PZX54(P^)7CC)7}$'
b='EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf '%s%s' "$a" "$b" > ./eg-eicar.com
printf '#!/bin/sh\necho eg-probe\n' > ./eg-dropped.sh
chmod 0755 ./eg-dropped.sh
echo "RESULT drop-files $(wc -c < ./eg-eicar.com) $(wc -c < ./eg-dropped.sh)"
