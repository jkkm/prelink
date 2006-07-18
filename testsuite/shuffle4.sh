#!/bin/sh
rm -f shuffle4 shuffle4.log
$CCLINK -o shuffle4 $srcdir/shuffle2.c -Wl,--rpath-link,. shuffle3lib2.so
echo $PRELINK -vm ./shuffle4 > shuffle4.log
$PRELINK -vm ./shuffle4 >> shuffle4.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle4.log && exit 2
LD_LIBRARY_PATH=. ./shuffle4 || exit 3
readelf -a ./shuffle4 >> shuffle4.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./shuffle4
