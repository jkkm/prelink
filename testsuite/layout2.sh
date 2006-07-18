#!/bin/sh
rm -f layout2 layout2lib*.so layout2.log
i=1
while [ $i -lt 6 ]; do
  $CXX -shared -fpic -o layout2lib$i.so $srcdir/layoutlib.C
  i=`expr $i + 1`
done
$CXXLINK -o layout2 $srcdir/layout.C layout2lib*.so
echo $PRELINK -vR ./layout2 > layout2.log
$PRELINK -vR ./layout2 >> layout2.log 2>&1 || exit 1
LD_LIBRARY_PATH=. ./layout2 || exit 2
readelf -a ./layout2 >> kayout2.log 2>&1 || exit 3
# So that it is not prelinked again
chmod -x ./layout2
