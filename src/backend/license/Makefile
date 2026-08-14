#-------------------------------------------------------------------------
#
# Makefile for src/backend/license
#
# Offline certificate based license verification.
#
# The trust anchor header is generated from the committed PEM at build time.
# The build never fetches a trust anchor over the network; see
# doc/LICENSE_ENFORCEMENT.md section 2.4.
#
# src/backend/license/Makefile
#
#-------------------------------------------------------------------------

subdir = src/backend/license
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

# license_core.o is deliberately free of PostgreSQL headers so the same source
# can be linked into the standalone harness under test/.
# license.o (postmaster glue) and license_bgworker.o (runtime expiry) are
# added by work order steps 4 and 5. Only what exists is listed, so the tree
# always builds.
OBJS = \
	$(WIN32RES) \
	ca_pin.o \
	license_core.o

include $(top_srcdir)/src/backend/common.mk

# Which PEM files become embedded trust anchors.
#
# LICENSE_CA_PEM can list more than one file so a CA rotation can ship a build
# that accepts both the outgoing and incoming root during the transition.
#
# A test build sets LICENSE_DEV_CA_PEM to embed a development CA INSTEAD OF the
# production CA, never in addition to it. CI inspects the shipped binary and
# fails if a dev CA fingerprint appears in a release artifact.
LICENSE_CA_PEM ?= $(srcdir)/appscode_root_ca.pem

ifdef LICENSE_DEV_CA_PEM
LICENSE_ANCHORS = $(LICENSE_DEV_CA_PEM)
LICENSE_PIN_ARG = --pin-output dev_ca_pin.h
override CPPFLAGS := -DLICENSE_DEV_CA $(CPPFLAGS)
GENERATED_PIN = dev_ca_pin.h
else
LICENSE_ANCHORS = $(LICENSE_CA_PEM)
LICENSE_PIN_ARG =
GENERATED_PIN =
endif

appscode_root_ca.h $(GENERATED_PIN): $(LICENSE_ANCHORS) $(srcdir)/generate_ca_header.pl
	$(PERL) $(srcdir)/generate_ca_header.pl \
		--output appscode_root_ca.h $(LICENSE_PIN_ARG) $(LICENSE_ANCHORS)

# license_core.c includes the generated header, so ordering matters.
license_core.o: appscode_root_ca.h
ca_pin.o: $(GENERATED_PIN)

clean distclean:
	rm -f $(OBJS) appscode_root_ca.h dev_ca_pin.h
