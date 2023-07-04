# ARCH is target processor architecture
ARCH ?=
# CROSS_COMPILE is cross compiler prefix (including full path)
CROSS_COMPILE ?=
# KERNEL_SRC is the path to your kernel sources
KERNEL_SRC ?=

# Host architecture
HOST_ARCH ?= $(patsubst i%86,i386,$(shell uname -m))
ifeq ($(findstring ppc,$(HOST_ARCH)),ppc)
HOST_ARCH := powerpc
endif
ifeq ($(findstring arm,$(HOST_ARCH)),arm)
HOST_ARCH := arm
endif
ifeq ($(findstring aarch64,$(HOST_ARCH)),aarch64)
HOST_ARCH := arm64
endif
# Which kernel version to use
KERNEL_VERSION ?= $(shell uname -r)
# Where to install module
MODULESDIR ?= /lib/modules/${KERNEL_VERSION}
# Kernel source tree
HOST_KERNEL ?= ${MODULESDIR}/build

ifndef ARCH
ARCH := $(HOST_ARCH)
endif

# Building 32-bit binaries on 64-bit x86
ifeq ($(ARCH),i386) 
ifeq ($(HOST_ARCH),x86_64)
COMPAT := yes
endif
endif

ifeq ($(ARCH),$(HOST_ARCH))
ifndef KERNEL_SRC
KERNEL_SRC := $(HOST_KERNEL)
endif
else
ifndef KERNEL_SRC
ifdef NEED_KERNEL
$(error Please define KERNEL_SRC.)
endif
endif
endif

# Code coverage stuff...
ifneq ($(COVFILE),)
PATH := /usr/bin/bullseye/bin:$(PATH)
export COVFILE
endif

include $(LINX)/net/linx/common.mk

echo_config_target:
	$(error Bad default target config.mk)

echo_config:
	$(ECHO) "# ARCH=$(ARCH)"
ifdef CROSS_COMPILE
	$(ECHO) "# CROSS_COMPILE=$(CROSS_COMPILE)"
endif
ifdef KERNEL_SRC
	$(ECHO) "# KERNEL_SRC=$(KERNEL_SRC)"
endif
ifdef VERBOSE
	$(ECHO) "# VERBOSE=$(VERBOSE)"
else
	$(ECHO) "# VERBOSE=no"
endif

export ARCH CROSS_COMPILE KERNEL_SRC LINX

.PHONY: echo_config

# If UML, let the host that runs UML decide,                                                                                         
# otherwise use ARCH... 
ifeq ($(ARCH),um)
MACHINE = $(strip $(shell uname -m))
else
MACHINE = $(ARCH)
endif

ifeq ($(MACHINE),mips)
ENDIAN_SUPPORT := BIG_ENDIAN
endif

ifeq ($(MACHINE),mips64)
ENDIAN_SUPPORT := BIG_ENDIAN
64BIT_SUPPORT = yes
endif

ifeq ($(MACHINE),ppc)
ENDIAN_SUPPORT := BIG_ENDIAN
endif

ifeq ($(MACHINE),ppc64)
ENDIAN_SUPPORT := BIG_ENDIAN
64BIT_SUPPORT = yes
endif

ifeq ($(MACHINE), powerpc)
ENDIAN_SUPPORT := BIG_ENDIAN
endif

ifeq ($(MACHINE), arm64)
64BIT_SUPPORT = yes
endif

ifeq ($(MACHINE),x86_64)
64BIT_SUPPORT = yes
endif

ENDIAN_SUPPORT ?= LITTLE_ENDIAN

ifeq ($(ENDIAN_SUPPORT),BIG_ENDIAN)
EXTRA_CFLAGS += -DRLNH_BIG_ENDIAN
else
EXTRA_CFLAGS += -DRLNH_LITTLE_ENDIAN
endif

# Local configuration for ppc and x86
ifeq ($(ARCH),ppc)
# This patch is needed to resolve strange includes
# in the mercury linux distribution.
EXTRA_CFLAGS += -I$(KDIR)/arch/ppc -DRLNH_ALIGN_ANY
else # x86
KDIR  := /lib/modules/$(KERNEL_VERSION)/build
endif
