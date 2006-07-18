#!/bin/sh
. `dirname $0`/functions.sh
# This script copies needed C and C++ libraries into the test directory
echo 'int main() { }' > movelibs.C
$CXX -o movelibs movelibs.C
> syslib.list
for i in `ldd ./movelibs | awk ' { print $3 } '`; do
  if [ -L $i ]; then
    j=`ls -l $i | sed 's/^.* -> //'`
    k=`basename $i`
    if echo $j | grep / >/dev/null 2>&1; then
      cp -p $i .
      cp -p $k $k.orig
      echo $k >> syslib.list
    else
      cp -dp $i .
      cp -p `dirname $i`/$j .
      cp -p $j $j.orig
      echo $j >> syslib.list
    fi
  else
    cp -p $i .
    cp -p $k $k.orig
    echo $k >> syslib.list
  fi
done
rm -f movelibs.C movelibs
pwd > prelink.conf
exit 77
