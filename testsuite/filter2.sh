#!/bin/sh
# This test relies on current GNU libc DT_FILTER/DT_AUXILIARY handling
#
rm -f filter2 filter2lib*.so filter2.log
rm -f prelink.cache
$CC -shared -O2 -fpic -o filter2filter.so $srcdir/filter1filter.c
$CC -shared -O2 -fpic -o filter2lib1.so $srcdir/filter1lib1.c -Wl,-F,filter2filter.so -Wl,-f,filter2missingfilter.so filter2filter.so
$CC -shared -O2 -fpic -o filter2lib2.so $srcdir/filter1lib2.c filter2lib1.so
$CCLINK -o filter2 $srcdir/filter1.c -Wl,--rpath-link,. filter2lib2.so
echo $PRELINK -vm ./filter2 > filter2.log
$PRELINK -vm ./filter2 >> filter2.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` filter2.log && exit 2
LD_LIBRARY_PATH=. ./filter2 || exit 3
readelf -a ./filter2 >> filter2.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./filter2
