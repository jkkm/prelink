#!/bin/sh
rm -f reloc3 reloc3lib*.so reloc3.log reloc3.lds
rm -f prelink.cache
$CC -shared -O2 -fpic -o reloc3lib1.so $srcdir/reloc1lib1.c
$CC -shared -O2 -fpic -o reloc3lib2.so $srcdir/reloc1lib2.c reloc3lib1.so
$CCLINK -o reloc3 $srcdir/reloc1.c -Wl,--rpath-link,. reloc3lib2.so \
  -Wl,--verbose 2>&1 | sed -e '/^=========/,/^=========/!d;/^=========/d' \
  -e 's/0x08048000/0x08000000/;s/SIZEOF_HEADERS.*$/& . += 56;/' > reloc3.lds
$CCLINK -o reloc3 $srcdir/reloc1.c -Wl,--rpath-link,. reloc3lib2.so \
  -Wl,-T,reloc3.lds
echo $PRELINK -vm ./reloc3 > reloc3.log
$PRELINK -vm ./reloc3 >> reloc3.log 2>&1 || exit 1
LD_LIBRARY_PATH=. ./reloc3 || exit 2
readelf -a ./reloc3 >> reloc3.log 2>&1 || exit 3
# So that it is not prelinked again
chmod -x ./reloc3
