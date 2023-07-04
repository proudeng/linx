# Makefile.am for linxcfg

LIBLINX = ../lib/liblinx.a
LIBCFG  = ../lib/liblinxcfg.a
LDADD = ../lib/liblinxcfg.a

LIB = ../lib
LINXROOT = ..

include $(LINXROOT)/flags.am

dist_man1_MANS = \
	$(LINXROOT)/doc/man1/linxcfg.1 \
	$(LINXROOT)/doc/man1/mkethcon.1 \
	$(LINXROOT)/doc/man1/mklink.1 \
	$(LINXROOT)/doc/man1/mktcpcon.1 \
	$(LINXROOT)/doc/man1/rmethcon.1 \
	$(LINXROOT)/doc/man1/rmlink.1 \
	$(LINXROOT)/doc/man1/rmtcpcon.1 \
	$(LINXROOT)/doc/man1/mkshmcon.1 \
	$(LINXROOT)/doc/man1/rmshmcon.1 \
	$(LINXROOT)/doc/man1/mkriocon.1 \
	$(LINXROOT)/doc/man1/rmriocon.1 \
	$(LINXROOT)/doc/man1/mkcmclcon.1 \
	$(LINXROOT)/doc/man1/rmcmclcon.1

nobase_include_HEADERS = \
	$(LINXROOT)/include/linxcfg.h \
	$(LINXROOT)/include/linux/ethcm_db_ioctl.h \
	$(LINXROOT)/include/linux/rlnh_db_ioctl.h \
	$(LINXROOT)/include/linux/tcpcm_db_ioctl.h \
	$(LINXROOT)/include/linux/shmcm_db_ioctl.h \
	$(LINXROOT)/include/linux/cmcl_db_ioctl.h \
	$(LINXROOT)/include/linux/riocm_db_ioctl.h \
	$(LINXROOT)/include/db_ioctl.h \
	$(LINXROOT)/include/ethcm_db_ioctl.h \
	$(LINXROOT)/include/rlnh_db_ioctl.h \
	$(LINXROOT)/include/tcpcm_db_ioctl.h \
	$(LINXROOT)/include/shmcm_db_ioctl.h \
	$(LINXROOT)/include/riocm_db_ioctl.h \
	$(LINXROOT)/include/cmcl_db_ioctl.h

AM_CPPFLAGS = $(DEPS_CFLAGS)

bin_PROGRAMS =  $(LINXROOT)/bin/mkethcon \
		$(LINXROOT)/bin/linxcfg  \
		$(LINXROOT)/bin/mklink   \
		$(LINXROOT)/bin/rmlink   \
		$(LINXROOT)/bin/rmethcon \
		$(LINXROOT)/bin/mktcpcon \
		$(LINXROOT)/bin/rmtcpcon \
		$(LINXROOT)/bin/mkshmcon \
		$(LINXROOT)/bin/rmshmcon \
		$(LINXROOT)/bin/mkriocon \
		$(LINXROOT)/bin/rmriocon \
		$(LINXROOT)/bin/mkcmclcon \
		$(LINXROOT)/bin/rmcmclcon

__LINXROOT__bin_mkethcon_SOURCES =  mkethcon.c
__LINXROOT__bin_mkethcon_LDADD   = $(LIBLINX) $(LIBCFG)

__LINXROOT__bin_linxcfg_SOURCES = linx_cfg_eth.c \
		  linx_cfg_rio.c \
		  linx_cfg_tcp.c \
                  linx_cfg_cmcl.c \
                  linx_cfg_cm.h \
		  linxcfg.c \
                  linx_cfg.h \
		  config.c \
                  config.h
__LINXROOT__bin_linxcfg_LDADD =  $(LIBLINX) $(LIBCFG)

__LINXROOT__bin_rmethcon_SOURCES =  rmethcon.c

__LINXROOT__bin_mkriocon_SOURCES =  mkriocon.c
__LINXROOT__bin_mkriocon_LDADD   =  $(LIBLINX) $(LIBCFG)

__LINXROOT__bin_rmriocon_SOURCES =  rmriocon.c

__LINXROOT__bin_mktcpcon_SOURCES =  mktcpcon.c

__LINXROOT__bin_rmtcpcon_SOURCES =  rmtcpcon.c

__LINXROOT__bin_mkshmcon_SOURCES =  mkshmcon.c

__LINXROOT__bin_rmshmcon_SOURCES = rmshmcon.c

__LINXROOT__bin_mkcmclcon_SOURCES =  mkcmclcon.c

__LINXROOT__bin_rmcmclcon_SOURCES = rmcmclcon.c

__LINXROOT__bin_mklink_SOURCES =  mklink.c

__LINXROOT__bin_rmlink_SOURCES =  rmlink.c

lib_LTLIBRARIES = $(LIB)/liblinxcfg.la
noinst_LIBRARIES = $(LIB)/liblinxcfg.a

__LIB__liblinxcfg_la_SOURCES = db_utils.c \
		  cmcl_utils.c \
		  ethcm_utils.c \
		  riocm_utils.c \
		  shmcm_utils.c \
		  tcpcm_utils.c \
		  rlnh_utils.c \
		  libcfg.c \
		  riocm_utils.h \
		  rlnh_utils.h \
		  shmcm_utils.h\
		  ethcm_utils.h \
		  tcpcm_utils.h \
		  cmcl_utils.h \
		  linx_cfg.h \
		  db_utils.h

__LIB__liblinxcfg_a_SOURCES = $(__LIB__liblinxcfg_la_SOURCES)

INCLUDES = -I $(LINXROOT)/include/
__LIB__liblinxcfg_la_LDFLAGS = $(all_libraries)

__LIB__liblinxcfg_la_CFLAGS = -c -Wall -pedantic -std=gnu99 -O2
__LIB__liblinxcfg_a_CFLAGS = -c -Wall -pedantic -std=gnu99 -O2

AM_CFLAGS = -I../include
AM_CFLAGS += -I../net/linx/include
AM_CFLAGS += -I../linxcfg
AM_CFLAGS += -O2 -std=gnu99
AM_CFLAGS += -DUSER_SPACE_COMMAND
AM_CFLAGS += -Wall
LINX ?= $(PWD)/..

