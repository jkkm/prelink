#!/bin/sh
case "`uname -m`" in
  ia64) exit 77;; # Does not support non-pic shared libs
esac
rm -f test03 lib03*.so test03.log
$CC -shared -O2 -o lib031.so $srcdir/lib031.c
$CC -shared -O2 -o lib032.so $srcdir/lib032.c lib031.so
$CCLINK -o test03 $srcdir/test03.c -Wl,--rpath-link,. lib032.so
echo $PRELINK -vm ./test03 > test03.log
$PRELINK -vm ./test03 >> test03.log 2>&1 || exit 1
LD_LIBRARY_PATH=. ./test03 || exit 2
# So that it is not prelinked again
chmod -x ./test03
