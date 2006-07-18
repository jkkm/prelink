#!/bin/sh
rm -f test02 lib02*.so test02.log
rm -f prelink.cache
$CC -shared -O2 -fpic -o lib021.so $srcdir/lib021.c
$CC -shared -O2 -fpic -o lib022.so $srcdir/lib022.c lib021.so
$CCLINK -o test02 $srcdir/test02.c -Wl,--rpath-link,. lib022.so
echo $PRELINK -vm ./test02 > test02.log
$PRELINK -vm ./test02 >> test02.log 2>&1 || exit 1
LD_LIBRARY_PATH=. ./test02 || exit 2
# So that it is not prelinked again
chmod -x ./test02
