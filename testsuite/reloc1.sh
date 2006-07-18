#!/bin/sh
rm -f reloc1 reloc1lib*.so reloc1.log
rm -f prelink.cache
$CC -shared -O2 -fpic -o reloc1lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o reloc1lib2.so $srcdir/reloc1lib2.c reloc1lib1.so
cp -a reloc1lib1.so reloc1lib1.so.orig
cp -a reloc1lib2.so reloc1lib2.so.orig
$CCLINK -o reloc1 $srcdir/reloc1.c -Wl,--rpath-link,. reloc1lib2.so
echo $PRELINK -vm ./reloc1 > reloc1.log
$PRELINK -vm ./reloc1 >> reloc1.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc1.log && exit 2
LD_LIBRARY_PATH=. ./reloc1 || exit 3
readelf -a ./reloc1 >> reloc1.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./reloc1
