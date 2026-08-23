# Copyright (c) 2022-2023, PostgreSQL Global Development Group
#
# AppsCode license enforcement.
#
# License verification links OpenSSL unconditionally, so the AppsCode build
# requires -Dssl=openssl. The embedded trust anchor is selected at configure
# time: by default the production CA at appscode_root_ca.pem, or a dev CA via
# -Dappscode_license_dev_ca=/path/to/dev-ca.pem for test builds. A dev CA
# must never ship in a release binary.

if not ssl.found()
  error('the AppsCode build requires OpenSSL for license enforcement; configure with -Dssl=openssl')
endif

license_dev_ca = get_option('appscode_license_dev_ca')
license_gen = files('generate-ca-header.py')

license_c_args = []
license_extra_gen = []

if license_dev_ca != ''
  license_ca_pem = license_dev_ca
  license_c_args += '-DAPPSCODE_LICENSE_DEV_BUILD'

  # Dev build: also generate the pins header for the random dev CA.
  license_pins_h = custom_target('appscode_root_ca_pins.h',
    output: 'appscode_root_ca_pins.h',
    input: license_gen,
    command: [
      python, '@INPUT@',
      '--pem', license_ca_pem,
      '--pins-out', '@OUTPUT@',
    ],
  )
  license_extra_gen += license_pins_h
else
  license_ca_pem = meson.current_source_dir() / 'appscode_root_ca.pem'
endif

# DER header, generated for every build. license.c includes it.
license_der_h = custom_target('appscode_root_ca_der.h',
  output: 'appscode_root_ca_der.h',
  input: license_gen,
  command: [
    python, '@INPUT@',
    '--pem', license_ca_pem,
    '--der-out', '@OUTPUT@',
  ],
)

# Build the license code as its own static library so the generated-header
# build directory and the OpenSSL dependency stay scoped to it; link it into
# the backend. Listing the custom targets in the sources adds their build
# directory to this library's include path.
license_lib = static_library('license_srv',
  files(
    'license.c',
    'license_check.c',
    'license_pins.c',
    'license_state.c',
  ),
  license_der_h,
  license_extra_gen,
  c_args: license_c_args,
  dependencies: backend_build_deps + [ssl],
  include_directories: [postgres_inc, include_directories('.')],
  kwargs: internal_lib_args,
)

backend_link_with += license_lib
