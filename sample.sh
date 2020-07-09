#!/bin/sh
find "${@}" -type f -exec edonkey-tool-hash "{}" ";" |
while read hash
do
	echo "${hash}"
	./aniupdate +mylist "${hash}"
done
#eof
