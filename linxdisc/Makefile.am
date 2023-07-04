# Makefile.am for linxdisc

LINXROOT = ..
INCLUDES = -I ../include/

dist_man5_MANS = $(LINXROOT)/doc/man5/linxdisc.conf.5
dist_man8_MANS = $(LINXROOT)/doc/man8/linxdisc.8

LIBLINX = $(LINXROOT)/lib/liblinx.a
LIBCFG  = $(LINXROOT)/lib/liblinxcfg.a

bin_PROGRAMS    = $(LINXROOT)/bin/linxdisc
__LINXROOT__bin_linxdisc_SOURCES = config.c \
		   debug.c \
		   linxdisc.h \
		   linxdisc.c \
		   util.c

__LINXROOT__bin_linxdisc_LDADD = $(LIBCFG) $(LIBLINX)
__LINXROOT__bin_linxdisc_CFLAGS = -O2 -Wall -pedantic -std=gnu99 -D_GNU_SOURCE

if !DEBUG
__LINXROOT__bin_linxdisc_CFLAGS += -DNDEBUG
endif



