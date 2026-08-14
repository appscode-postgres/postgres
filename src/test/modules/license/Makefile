# src/test/modules/license/Makefile
#
# These tests need a server built with a development CA embedded INSTEAD OF the
# production AppsCode CA, and PG_LICENSE_DEV_CA pointing at that CA directory.
# Without it every test file skips rather than reporting confusing chain
# failures. See t/001_startup.pl for the build recipe.

TAP_TESTS = 1

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = src/test/modules/license
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global
export PG_LICENSE_SRCDIR = $(abs_top_srcdir)
include $(top_srcdir)/contrib/contrib-global.mk
endif
