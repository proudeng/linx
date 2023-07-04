# Makefile.am for liblinx

LIB   = ../lib
LINXROOT = ..
INCLUDES = -I $(LINXROOT)/include/

dist_man3_MANS = \
	$(LINXROOT)/doc/man3/linx.h.3 \
	$(LINXROOT)/doc/man3/linx_alloc.3 \
	$(LINXROOT)/doc/man3/linx_attach.3 \
	$(LINXROOT)/doc/man3/linx_close.3 \
	$(LINXROOT)/doc/man3/linx_detach.3 \
	$(LINXROOT)/doc/man3/linx_free_buf.3 \
	$(LINXROOT)/doc/man3/linx_get_descriptor.3 \
	$(LINXROOT)/doc/man3/linx_get_name.3 \
	$(LINXROOT)/doc/man3/linx_get_spid.3 \
	$(LINXROOT)/doc/man3/linx_hunt.3 \
	$(LINXROOT)/doc/man3/linx_hunt_from.3 \
	$(LINXROOT)/doc/man3/linx_open.3 \
	$(LINXROOT)/doc/man3/linx_receive.3 \
	$(LINXROOT)/doc/man3/linx_receive_from.3 \
	$(LINXROOT)/doc/man3/linx_receive_w_tmo.3 \
	$(LINXROOT)/doc/man3/linx_s_alloc.3 \
	$(LINXROOT)/doc/man3/linx_send.3 \
	$(LINXROOT)/doc/man3/linx_send_w_s.3 \
	$(LINXROOT)/doc/man3/linx_sender.3  \
	$(LINXROOT)/doc/man3/linx_set_sigsize.3 \
	$(LINXROOT)/doc/man3/linx_sigsize.3 \
	$(LINXROOT)/doc/man3/linx_types.h.3 \
	$(LINXROOT)/doc/man3/linx_free_name.3 \
	$(LINXROOT)/doc/man3/linx_free_stat.3 \
	$(LINXROOT)/doc/man3/linx_get_stat.3 \
	$(LINXROOT)/doc/man3/linx_cancel_tmo.3 \
	$(LINXROOT)/doc/man3/linx_modify_tmo.3 \
	$(LINXROOT)/doc/man3/linx_request_tmo.3 \
	$(LINXROOT)/doc/man3/linx_send_w_opt.3 \
	$(LINXROOT)/doc/man3/linx_sigattr.3 \
	$(LINXROOT)/doc/man3/linx_get_owner.3 \
	$(LINXROOT)/doc/man3/linx_get_version.3 \
	$(LINXROOT)/doc/man3/linx_cancel_new_link.3 \
	$(LINXROOT)/doc/man3/linx_request_new_link.3

dist_man7_MANS = $(LINXROOT)/doc/man7/linx.7

include $(LINXROOT)/flags.am

nobase_include_HEADERS = \
	$(LINXROOT)/include/linx.h \
	$(LINXROOT)/include/linx_ioctl.h \
	$(LINXROOT)/include/linx_socket.h \
	$(LINXROOT)/include/linx_types.h \
	$(LINXROOT)/include/linux/linx_ioctl.h \
	$(LINXROOT)/include/linux/linx_socket.h \
	$(LINXROOT)/include/linux/linx_types.h \
	$(LINXROOT)/include/linux/db_ioctl.h \
	$(LINXROOT)/include/linux/db_types.h \
	$(LINXROOT)/include/linux/mailbox.h

lib_LTLIBRARIES = $(LIB)/liblinx.la
noinst_LIBRARIES = $(LIB)/liblinx.a

__LIB__liblinx_la_SOURCES = linx.c
__LIB__liblinx_la_LDFLAGS = $(all_libraries)
__LIB__liblinx_la_CFLAGS = -c -Wall -pedantic -std=gnu99 -O2

__LIB__liblinx_a_SOURCES = linx.c
__LIB__liblinx_a_CFLAGS = -c -Wall -pedantic -std=gnu99 -O2

if !DEBUG
__LIB__liblinx_la_CFLAGS += -DNDEBUG
__LIB__liblinx_a_CFLAGS += -DNDEBUG
endif