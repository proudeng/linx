# RIO Makefile

all: modules

LINX ?= $(CURDIR)/../../..
include $(LINX)/net/linx/config.mk

VENDOR_VERSION := $(shell make -C $(KERNEL_SRC) ARCH=$(ARCH) kernelversion)
KERNEL_CODE	   := $(shell if [ -f $(KERNEL_SRC)/include/generated/uapi/linux/version.h ]; \
                          then awk '/LINUX_VERSION_CODE/ {print $$3}' $(KERNEL_SRC)/include/generated/uapi/linux/version.h; \
                          else awk '/LINUX_VERSION_CODE/ {print $$3}' $(KERNEL_SRC)/include/linux/version.h; \
                          fi)

ifneq ($(VENDOR_VERSION), "")
	EXTRA_CFLAGS += -DGFP_IS_INT
endif

# Kernel version codes
2_6_13 := 132621

# 'gt_or_eq'
gt_or_eq = $(findstring $(1),$(word 2,$(sort $(2) $(1))))

ifeq ($(call gt_or_eq,$(KERNEL_CODE),$(2_6_13)),$(KERNEL_CODE)) 
  EXTRA_CFLAGS += -DRIO_COMPAT
else
  ifeq ($(findstring 2.6.10_mvlcge401,$(VENDOR_VERSION)),2.6.10_mvlcge401)
    EXTRA_CFLAGS += -DRIO_COMPAT
  else
    EXTRA_CFLAGS += -DRIO_KZALLOC	
  endif
endif

EXTRA_CFLAGS += -Wall
ifeq ($(EXTRA_WARNINGS),yes)
EXTRA_CFLAGS += -Wextra #  -Wno-unused-parameter -Wno-sign-compare
endif
EXTRA_CFLAGS += -I$(LINX)/include -I$(LINX)/net/linx \
		-I$(LINX)/net/linx/include \
                -I$(LINX)/net/linx/riocm

obj-m := linx_rio_cm.o

linx_rio_cm-y += rio_conn.o
linx_rio_cm-y += rio_tx.o
linx_rio_cm-y += rio_rx.o
linx_rio_cm-y += rio_kutils.o

SRC := $(shell pwd)

modules:
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL_SRC) M=$(SRC) modules
	$(CP) linx_rio_cm.ko ..

clean:
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL_SRC) M=$(SRC) clean
	$(LINXRM) Module.symvers Module.markers modules.order ../linx_rio_cm.ko

modules_install: modules
	$(XMAKE) ARCH=$(ARCH) V=$(V) -C $(KERNEL_SRC) M=$(SRC) modules_install
	depmod

