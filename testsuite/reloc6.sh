#!/bin/sh
rm -f reloc6 reloc6lib*.so reloc6.log
rm -f prelink.cache
$CC -shared -O2 -fpic -o reloc6lib1.so $srcdir/reloc3lib1.c
$CC -shared -O2 -fpic -o reloc6lib2.so $srcdir/reloc1lib2.c reloc6lib1.so
cp -a reloc6lib1.so reloc6lib1.so.orig
cp -a reloc6lib2.so reloc6lib2.so.orig
$CCLINK -o reloc6 $srcdir/reloc3.c -Wl,--rpath-link,. reloc6lib2.so
$CCLINK -o reloc6.nop $srcdir/reloc3.c -Wl,--rpath-link,. reloc6lib2.so
echo $PRELINK -vm ./reloc6 > reloc6.log
$PRELINK -vm ./reloc6 >> reloc6.log 2>&1 || exit 1
grep -q ^`echo $PRELINK | sed 's/ .*$/: /'` reloc6.log && exit 2
LD_LIBRARY_PATH=. ./reloc6 >> reloc6.log || exit 3
readelf -a ./reloc6 >> reloc6.log 2>&1 || exit 4
LD_LIBRARY_PATH=. ./reloc6.nop >> reloc6.log || exit 5
LD_LIBRARY_PATH=. LD_BIND_NOW=1 ./reloc6.nop >> reloc6.log || exit 6
mv -f reloc6lib2.so reloc6lib2.so.p
$CC -shared -O2 -fpic -o reloc6lib2.so $srcdir/reloc1lib2.c reloc6lib1.so
LD_LIBRARY_PATH=. ./reloc6 >> reloc6.log || exit 7
LD_LIBRARY_PATH=. ./reloc6.nop >> reloc6.log || exit 8
LD_LIBRARY_PATH=. LD_BIND_NOW=1 ./reloc6.nop >> reloc6.log || exit 9
mv -f reloc6lib2.so reloc6lib2.so.nop
mv -f reloc6lib2.so.p reloc6lib2.so
# So that it is not prelinked again
chmod -x ./reloc6 ./reloc6.nop
