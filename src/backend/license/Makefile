#-------------------------------------------------------------------------
#
# Makefile for backend/license
#
# AppsCode license enforcement. Compiles the verification core, the state
# module and the backend glue into the server, and generates the embedded
# trust-anchor header from a PEM file.
#
# The embedded CA is selected at build time:
#   * Release (default): embeds src/backend/license/appscode_root_ca.pem and
#     uses the hand-written production pins in license_pins.c.
#   * Dev/test: set APPSCODE_LICENSE_DEV_CA=/path/to/dev-ca.pem on the make
#     command line. That PEM is embedded instead, APPSCODE_LICENSE_DEV_BUILD
#     is defined, and a matching pins header is generated. A dev CA must
#     never ship in a release binary (see the CI gate in the docs).
#
# IDENTIFICATION
#    src/backend/license/Makefile
#
#-------------------------------------------------------------------------

subdir = src/backend/license
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

OBJS = \
	license.o \
	license_check.o \
	license_pins.o \
	license_state.o

# Select the embedded CA and whether this is a dev build.
ifdef APPSCODE_LICENSE_DEV_CA
CA_PEM = $(APPSCODE_LICENSE_DEV_CA)
override CPPFLAGS := -DAPPSCODE_LICENSE_DEV_BUILD -I. $(CPPFLAGS)
GEN_PINS_ARG = --pins-out appscode_root_ca_pins.h
GENERATED_PINS_HEADER = appscode_root_ca_pins.h
else
CA_PEM = $(srcdir)/appscode_root_ca.pem
override CPPFLAGS := -I. $(CPPFLAGS)
GEN_PINS_ARG =
GENERATED_PINS_HEADER =
endif

# Allow overriding the compiled-in default license path.
ifdef APPSCODE_LICENSE_DEFAULT_PATH
override CPPFLAGS := -DAPPSCODE_LICENSE_DEFAULT_PATH='"$(APPSCODE_LICENSE_DEFAULT_PATH)"' $(CPPFLAGS)
endif

include $(top_srcdir)/src/backend/common.mk

# Generated embedded trust-anchor header. license.c includes it; the dev
# build also generates the pins header, included by license_pins.c.
appscode_root_ca_der.h: $(CA_PEM) $(srcdir)/generate-ca-header.py
	$(PYTHON) $(srcdir)/generate-ca-header.py --pem $(CA_PEM) \
		--der-out appscode_root_ca_der.h $(GEN_PINS_ARG)

license.o: appscode_root_ca_der.h
ifdef APPSCODE_LICENSE_DEV_CA
license_pins.o: appscode_root_ca_der.h
endif

clean: clean-license
clean-license:
	rm -f appscode_root_ca_der.h appscode_root_ca_pins.h
