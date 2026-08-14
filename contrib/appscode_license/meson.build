# Copyright (c) 2022-2025, PostgreSQL Global Development Group

appscode_license_sources = files(
  'appscode_license.c',
)

if host_system == 'windows'
  appscode_license_sources += rc_lib_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'appscode_license',
    '--FILEDESC', 'appscode_license - read-only view of the verified license',])
endif

appscode_license = shared_module('appscode_license',
  appscode_license_sources,
  kwargs: contrib_mod_args,
)
contrib_targets += appscode_license

install_data(
  'appscode_license.control',
  'appscode_license--1.0.sql',
  kwargs: contrib_data_args,
)
