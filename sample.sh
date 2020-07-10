#!/bin/sh
find "${@}" -type f \( -name *.mkv -o -name *.avi -o -name *.mp4 \) -exec edonkey-tool-hash "{}" ";" |
while read hash
do
	echo "${hash}"
	./aniupdate +mylist "${hash}"
done
#eof
