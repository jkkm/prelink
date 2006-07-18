## Process this file with automake to create Makefile.in

AUTOMAKE_OPTIONS = 1.4 gnu

DEFS = -D_GNU_SOURCE -DHAVE_CONFIG_H -Wall
AM_CFLAGS = -Wall
INCLUDES = @GELFINCLUDE@

sbin_PROGRAMS = prelink

prelink_SYSDEPS = arch-i386.c
prelink_SOURCES = cache.c data.c doit.c dso.c dwarf2.c dwarf2.h exec.c	    \
		  execle_open.c get.c gather.c hashtab.c hashtab.h layout.c \
		  main.c prelink.c prelink.h prelinktab.h reloc.c reloc.h   \
		  stabs.c crc32.c \
		  $(prelink_SYSDEPS)
prelink_LDADD = @LIBGELF@

extra_DIST = makecrc.c
