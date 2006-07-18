#!/bin/sh
. `dirname $0`/functions.sh
rm -f reloc9 reloc9lib*.so reloc9.log
rm -f prelink.cache
$CC -shared -O2 -Wl,-z,nocombreloc -fpic -o reloc9lib1.so $srcdir/reloc3lib1.c
$CC -shared -O2 -Wl,-z,nocombreloc -fpic -o reloc9lib2.so $srcdir/reloc1lib2.c reloc9lib1.so
BINS="reloc9"
LIBS="reloc9lib1.so reloc9lib2.so"
$CCLINK -o reloc9 -Wl,-z,nocombreloc,-z,nocopyreloc $srcdir/reloc7.c -Wl,--rpath-link,. reloc9lib2.so
savelibs
echo $PRELINK -vm ./reloc9 > reloc9.log
$PRELINK -vm ./reloc9 >> reloc9.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc9.log && exit 2
LD_LIBRARY_PATH=. ./reloc9 >> reloc9.log || exit 3
readelf -a ./reloc9 >> reloc9.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./reloc9
comparelibs >> reloc9.log 2>&1 || exit 5
