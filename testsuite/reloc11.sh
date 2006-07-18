#!/bin/sh
. `dirname $0`/functions.sh
rm -f reloc1 reloc11lib*.so reloc11.log
rm -f prelink.cache
$CC -shared -O2 -nostdlib -fpic -o reloc11lib1.so $srcdir/reloc10lib4.c
BINS="reloc11"
LIBS="reloc11lib1.so"
$CCLINK -o reloc11 $srcdir/reloc11.c -Wl,--rpath-link,. reloc11lib1.so
savelibs
echo $PRELINK -vm ./reloc11 > reloc11.log
$PRELINK -vm ./reloc11 >> reloc11.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc11.log && exit 2
LD_LIBRARY_PATH=. ./reloc11 || exit 3
readelf -a ./reloc11 >> reloc11.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./reloc11
comparelibs >> reloc11.log 2>&1 || exit 5
