TOPDIR := $(shell pwd)
CFLAGS += -I$(TOPDIR)/../lib -I$(TOPDIR)/.. -I$(TOPDIR) -I$(TOPDIR)/gelfx -g -D_GNU_SOURCE -Wall
LDFLAGS += -L../obj/lib
LIBS = -lelf
SYSDEPS = $(patsubst %.c,%.o,$(wildcard sysdeps/*.c))
prelink: main.o dso.o data.o prelink.o cache.o exec.o get.o reloc.o $(SYSDEPS) gelfx/gelfx.o
	$(CC) $(LDFLAGS) -g -o $@ $^ -lelf
clean:
	rm -f *~ core *.o sysdeps/*~ sysdeps/*.o prelink gelfx*/*~ gelfx*/*.o
