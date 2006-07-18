#!/bin/sh
rm -f prelink.cache
rm -f layout1 layoutlib*.so layout1.log
i=10
while [ $i -lt 74 ]; do
  $CXX -shared -fpic -o layout1lib$i.so $srcdir/layoutlib.C
  i=`expr $i + 1`
done
$CXXLINK -o layout1 $srcdir/layout.C layout1lib*.so
echo $PRELINK -vR ./layout1 > layout1.log
$PRELINK -vR ./layout1 >> layout1.log 2>&1 || exit 1
LD_LIBRARY_PATH=. ./layout1 || exit 2
readelf -a ./layout1 >> kayout1.log 2>&1 || exit 3
# So that it is not prelinked again
chmod -x ./layout1
