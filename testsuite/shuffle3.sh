#!/bin/sh
rm -f shuffle3 shuffle3lib*.so shuffle3.log shuffle3.lds
rm -f prelink.cache
$CC -shared -O2 -fpic -o shuffle3lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o shuffle3lib2.so $srcdir/reloc1lib2.c shuffle3lib1.so
$CCLINK -o shuffle3 $srcdir/shuffle2.c -Wl,--rpath-link,. shuffle3lib2.so \
  -Wl,--verbose 2>&1 | sed -e '/^=========/,/^=========/!d;/^=========/d' \
  -e 's/0x08048000/0x08000000/' > shuffle3.lds
$CCLINK -o shuffle3 $srcdir/shuffle2.c -Wl,--rpath-link,. shuffle3lib2.so \
  -Wl,-T,shuffle3.lds
echo $PRELINK -vm ./shuffle3 > shuffle3.log
$PRELINK -vm ./shuffle3 >> shuffle3.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle3.log && exit 2
LD_LIBRARY_PATH=. ./shuffle3 || exit 3
readelf -a ./shuffle3 >> shuffle3.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./shuffle3
