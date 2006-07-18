srcdir=`dirname $0` CC=gcc CXX=g++ \
PRELINK="../src/prelink -c ./prelink.conf -C ./prelink.cache --ld-library-path=. --dynamic-linker=`echo ./ld*.so.*`" \
CCLINK="gcc -Wl,--dynamic-linker=`echo ./ld*.so.*`" \
CXXLINK="g++ -Wl,--dynamic-linker=`echo ./ld*.so.*`" /bin/sh "$@"
