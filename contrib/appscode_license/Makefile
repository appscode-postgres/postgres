# contrib/appscode_license/Makefile

MODULES = appscode_license
PGFILEDESC = "appscode_license - reporting for AppsCode license enforcement"

EXTENSION = appscode_license
DATA = appscode_license--1.0.sql

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
