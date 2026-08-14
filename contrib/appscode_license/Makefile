# contrib/appscode_license/Makefile

MODULE_big = appscode_license
OBJS = \
	$(WIN32RES) \
	appscode_license.o

EXTENSION = appscode_license
DATA = appscode_license--1.0.sql
PGFILEDESC = "appscode_license - read-only view of the verified license"

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/appscode_license
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
