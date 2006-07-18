#!/bin/sh
. `dirname $0`/functions.sh
rm -f reloc8 reloc8lib*.so reloc8.log
rm -f prelink.cache
$CC -shared -O2 -Wl,-z,nocombreloc -fpic -o reloc8lib1.so $srcdir/reloc3lib1.c
$CC -shared -O2 -Wl,-z,nocombreloc -fpic -o reloc8lib2.so $srcdir/reloc1lib2.c reloc8lib1.so
BINS="reloc8"
LIBS="reloc8lib1.so reloc8lib2.so"
$CCLINK -o reloc8 -Wl,-z,nocopyreloc $srcdir/reloc7.c -Wl,--rpath-link,. reloc8lib2.so
savelibs
echo $PRELINK -vm ./reloc8 > reloc8.log
$PRELINK -vm ./reloc8 >> reloc8.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc8.log && exit 2
LD_LIBRARY_PATH=. ./reloc8 >> reloc8.log || exit 3
readelf -a ./reloc8 >> reloc8.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./reloc8
comparelibs >> reloc8.log 2>&1 || exit 5
