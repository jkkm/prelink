## Process this file with automake to create Makefile.in

AUTOMAKE_OPTIONS = 1.4 gnu

DEFS = -D_GNU_SOURCE -DHAVE_CONFIG_H -Wall
AM_CFLAGS = -Wall

TESTS = movelibs.sh \
	reloc1.sh reloc2.sh reloc3.sh reloc4.sh reloc5.sh reloc6.sh \
	shuffle1.sh shuffle2.sh shuffle3.sh shuffle4.sh shuffle5.sh \
	layout1.sh layout2.sh
TESTS_ENVIRONMENT = \
	PRELINK="../src/prelink -c ./prelink.conf -C ./prelink.cache --ld-library-path=. --dynamic-linker=`echo ./ld*.so.*`" \
	CC="$(CC)" CCLINK="$(CC) -Wl,--dynamic-linker=`echo ./ld*.so.*`" \
	CXX="$(CXX)" CXXLINK="$(CXX) -Wl,--dynamic-linker=`echo ./ld*.so.*`" \
	$(SHELL)

extra_DIST = $(TESTS) env.sh

CLEANFILES = *.so *.so.* *.nop prelink.cache prelink.conf $(TESTS:%.sh=%) \
	$(TESTS:%.sh=%.log) $(TESTS:%.sh=%.lds) core *.\#prelink\#
