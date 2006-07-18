#!/bin/sh
rm -f reloc3 reloc3lib*.so reloc3.log
rm -f prelink.cache
$CC -shared -O2 -fpic -o reloc3lib1.so $srcdir/reloc3lib1.c
$CC -shared -O2 -fpic -o reloc3lib2.so $srcdir/reloc1lib2.c reloc3lib1.so
cp -a reloc3lib1.so reloc3lib1.so.orig
cp -a reloc3lib2.so reloc3lib2.so.orig
$CCLINK -o reloc3 $srcdir/reloc3.c -Wl,--rpath-link,. reloc3lib2.so
echo $PRELINK -vm ./reloc3 > reloc3.log
$PRELINK -vm ./reloc3 >> reloc3.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc3.log && exit 2
LD_LIBRARY_PATH=. ./reloc3 >> reloc3.log || exit 3
readelf -a ./reloc3 >> reloc3.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./reloc3
