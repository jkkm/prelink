## Process this file with automake to create Makefile.in

AUTOMAKE_OPTIONS = 1.4 gnu

DEFS = -D_GNU_SOURCE -DHAVE_CONFIG_H -Wall
AM_CFLAGS = -Wall
INCLUDES = @GELFINCLUDE@

sbin_PROGRAMS = prelink

prelink_SYSDEPS = arch-i386.c
prelink_SOURCES = cache.c data.c dso.c exec.c execle_open.c get.c gather.c \
		  hashtab.c hashtab.h main.c prelink.c prelink.h \
		  reloc.c reloc.h crc32.c \
		  $(prelink_SYSDEPS)
prelink_LDADD = @LIBGELF@

extra_DIST = makecrc.c
