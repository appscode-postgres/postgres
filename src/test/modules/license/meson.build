# Copyright (c) 2022-2023, PostgreSQL Global Development Group

tests += {
  'name': 'license',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'tap': {
    'env': {
      'APPSCODE_LICENSE_DEV_CA': get_option('appscode_license_dev_ca'),
    },
    'tests': [
      't/001_license.pl',
      't/002_license_runtime.pl',
    ],
  },
}
