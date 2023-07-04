# Makefile.am for linxgws

LIBGW = $(LINXROOT)/lib/libgw.a
LIBLINX = $(LINXROOT)/lib/liblinx.a
LINXROOT = ../..

dist_man5_MANS = $(LINXROOT)/doc/man5/linxgws.conf.5
dist_man8_MANS = $(LINXROOT)/doc/man8/linxgws.8

include $(LINXROOT)/flags.am

bin_PROGRAMS    = $(LINXROOT)/bin/linxgws

__LINXROOT__bin_linxgws_SOURCES = linxgws.c \
		  linxgws_main.c \
		  linxgws_msghandler.c \
		  linxgws.h \
		  linxgws_msghandler.h
__LINXROOT__bin_linxgws_LDADD = $(LIBLINX) $(LIBGW)

INCLUDES = -I ../include/ -I ../../include/

