#!/bin/sh
rm -f shuffle2 shuffle2lib*.so shuffle2.log shuffle2.lds
$CC -shared -O2 -fpic -o shuffle2lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o shuffle2lib2.so $srcdir/reloc1lib2.c shuffle2lib1.so
$CCLINK -o shuffle2 $srcdir/shuffle2.c -Wl,--rpath-link,. shuffle2lib2.so \
  -Wl,--verbose 2>&1 | sed -e '/^=========/,/^=========/!d;/^=========/d' \
  -e 's/0x08048000/0x08000000/;s/SIZEOF_HEADERS.*$/& . += 56;/' > shuffle2.lds
$CCLINK -o shuffle2 $srcdir/shuffle2.c -Wl,--rpath-link,. shuffle2lib2.so \
  -Wl,-T,shuffle2.lds
echo $PRELINK -vm ./shuffle2 > shuffle2.log
$PRELINK -vm ./shuffle2 >> shuffle2.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` shuffle2.log && exit 2
LD_LIBRARY_PATH=. ./shuffle2 || exit 3
readelf -a ./shuffle2 >> shuffle2.log 2>&1 || exit 4
# So that it is not prelinked again
chmod -x ./shuffle2
