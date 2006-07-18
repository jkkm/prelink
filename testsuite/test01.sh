#!/bin/sh
rm -f test01 lib01*.so test01.log
i=1
while [ $i -lt 6 ]; do
  $CXX -shared -fpic -o lib01$i.so $srcdir/lib00.C
  i=`expr $i + 1`
done
$CXXLINK -o test01 $srcdir/test00.C lib01*.so
echo $PRELINK -vR ./test01 > test01.log
$PRELINK -vR ./test01 >> test01.log 2>&1 || exit 1
LD_LIBRARY_PATH=. ./test01 || exit 2
# So that it is not prelinked again
chmod -x ./test01
