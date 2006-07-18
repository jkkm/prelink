#!/bin/sh
# This test relies on current GNU libc DT_FILTER/DT_AUXILIARY handling
#
rm -f filter1 filter1lib*.so filter1.log
rm -f prelink.cache
$CC -shared -O2 -fpic -o filter1filter.so $srcdir/filter1filter.c
$CC -shared -O2 -fpic -o filter1lib1.so $srcdir/filter1lib1.c -Wl,-F,filter1filter.so filter1filter.so
$CC -shared -O2 -fpic -o filter1lib2.so $srcdir/filter1lib2.c filter1lib1.so
$CCLINK -o filter1 $srcdir/filter1.c -Wl,--rpath-link,. filter1lib2.so
echo $PRELINK -vm ./filter1 > filter1.log
$PRELINK -vm ./filter1 >> filter1.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` filter1.log && exit 2
LD_LIBRARY_PATH=. ./filter1 || exit 3
readelf -a ./filter1 >> filter1.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./filter1
