## Process this file with automake to create Makefile.in

AUTOMAKE_OPTIONS = 1.4 gnu

DEFS = -D_GNU_SOURCE -DHAVE_CONFIG_H -Wall
AM_CFLAGS = -Wall

TESTS = movelibs.sh test00.sh test01.sh test02.sh test03.sh
TESTS_ENVIRONMENT = PRELINK="../src/prelink -c ./prelink.conf -C ./prelink.cache --ld-library-path=. --dynamic-linker=`echo ./ld*.so.*`" \
	CC="$(CC)" CCLINK="$(CC) -Wl,--dynamic-linker=`echo ./ld*.so.*`" \
	CXX="$(CXX)" CXXLINK="$(CXX) -Wl,--dynamic-linker=`echo ./ld*.so.*`" \
	$(SHELL)

extra_DIST = $(TESTS)

CLEANFILES = *.so *.so.* prelink.cache prelink.conf $(TESTS:%.sh=%) $(TESTS:%.sh=%.log)
