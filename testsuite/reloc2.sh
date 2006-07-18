#!/bin/sh
SHFLAGS=
case "`uname -m`" in
  ia64) SHFLAGS=-fpic;; # Does not support non-pic shared libs
esac
rm -f reloc2 reloc2lib*.so reloc2.log
$CC -shared $SHFLAGS -O2 -o reloc2lib1.so $srcdir/reloc2lib1.c
$CC -shared $SHFLAGS -O2 -o reloc2lib2.so $srcdir/reloc2lib2.c reloc2lib1.so
$CCLINK -o reloc2 $srcdir/reloc2.c -Wl,--rpath-link,. reloc2lib2.so
echo $PRELINK -vm ./reloc2 > reloc2.log
$PRELINK -vm ./reloc2 >> reloc2.log 2>&1 || exit 1
LD_LIBRARY_PATH=. ./reloc2 || exit 2
readelf -a ./reloc2 >> reloc2.log 2>&1 || exit 3
# So that it is not prelinked again
chmod -x ./reloc2
