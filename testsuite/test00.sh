#!/bin/sh
rm -f prelink.cache
rm -f test00 lib00*.so test00.log
i=10
while [ $i -lt 74 ]; do
  $CXX -shared -fpic -o lib00$i.so $srcdir/lib00.C
  i=`expr $i + 1`
done
$CXXLINK -o test00 $srcdir/test00.C lib00*.so
echo $PRELINK -vR ./test00 > test00.log
$PRELINK -vR ./test00 >> test00.log 2>&1 || exit 1
LD_LIBRARY_PATH=. ./test00 || exit 2
# So that it is not prelinked again
chmod -x ./test00
