#!/bin/sh
# This script copies needed C and C++ libraries into the test directory
echo 'int main() { }' > movelibs.C
$CXX -o movelibs movelibs.C
for i in `ldd ./movelibs | awk ' { print $3 } '`; do
  if [ -L $i ]; then
    j=`ls -l $i | sed 's/^.* -> //'`
    if echo $j | grep / >/dev/null 2>&1; then
      cp -p $i .
    else
      cp -dp $i .
      cp -p `dirname $i`/$j .
    fi
  else
    cp -p $i .
  fi
done
rm -f movelibs.C movelibs
pwd > prelink.conf
exit 77
