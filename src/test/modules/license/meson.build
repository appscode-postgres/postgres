# Copyright (c) 2022-2025, PostgreSQL Global Development Group

# These tests need a server built with a development CA embedded instead of the
# production CA. Configure with -Dlicense_dev_ca=/path/to/dev-ca/ca.crt and the
# suite finds the CA directory from that option, so no environment variable is
# needed. The directory must still contain ca.key, since the tests issue their
# own licenses.
#
# Without the option every test file skips rather than reporting confusing
# chain failures.

license_dev_ca_dir = ''
if get_option('license_dev_ca') != ''
  license_dev_ca_dir = fs.parent(get_option('license_dev_ca'))
endif

tests += {
  'name': 'license',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'tap': {
    'env': {
      'PG_LICENSE_SRCDIR': meson.source_root(),
      'PG_LICENSE_DEV_CA': license_dev_ca_dir,
    },
    'tests': [
      't/001_startup.pl',
      't/002_runtime.pl',
      't/003_state.pl',
    ],
  },
}
