#!/bin/sh
find "${@}" -type f -exec edonkey-tool-hash "{}" ";" |
while read hash
do
	echo "${hash}"
	./aniupdate.rb +add "${hash}"
done
#eof
