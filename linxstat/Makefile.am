# Makefile.am for linxstat
LINXROOT = ..
INCLUDES = -I ../include/

LIBLINX = $(LINXROOT)/lib/liblinx.a

dist_man1_MANS = $(LINXROOT)/doc/man1/linxstat.1

# linxstat_LDADD lists flags to the linker
LDADD = $(LIBLINX)

include $(LINXROOT)/flags.am

bin_PROGRAMS = $(LINXROOT)/bin/linxstat
__LINXROOT__bin_linxstat_SOURCES = linxstat.c \
		                   linx_info.c \
		                   linx_info.h


