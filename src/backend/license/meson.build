# Copyright (c) 2022-2025, PostgreSQL Global Development Group
#
# Offline certificate based license verification.
#
# The trust anchor header is generated from the committed PEM at build time.
# The build never fetches a trust anchor over the network; see
# doc/LICENSE_ENFORCEMENT.md section 2.4.

# Which PEM files become embedded trust anchors.
#
# A list, so a CA rotation can ship a build accepting both the outgoing and the
# incoming root during the transition.
#
# -Dlicense_dev_ca=<path> embeds a development CA INSTEAD OF the production CA,
# never in addition to it. CI inspects the shipped binary and fails if a dev CA
# fingerprint appears in a release artifact.
license_dev_ca = get_option('license_dev_ca')

license_cflags = []

if license_dev_ca != ''
  license_anchor_files = [files(license_dev_ca)]
  license_cflags += ['-DLICENSE_DEV_CA']
else
  license_anchor_files = [files('appscode_root_ca.pem')]
endif

license_ca_header = custom_target('appscode_root_ca.h',
  input: license_anchor_files,
  output: 'appscode_root_ca.h',
  command: [
    perl, files('generate_ca_header.pl'),
    '--output', '@OUTPUT@',
    '@INPUT@',
  ],
)
generated_backend_sources += license_ca_header

license_sources = files(
  'ca_pin.c',
  'license.c',
  'license_bgworker.c',
  'license_core.c',
)

# The dev CA pin cannot be hand maintained, since every developer generates
# their own dev CA, so it is generated alongside the DER bytes. The production
# pin stays hand written in ca_pin.c precisely so that replacing the committed
# PEM alone does not silently regenerate a matching digest.
if license_dev_ca != ''
  license_dev_pin = custom_target('dev_ca_pin.h',
    input: license_anchor_files,
    output: 'dev_ca_pin.h',
    command: [
      perl, files('generate_ca_header.pl'),
      '--pin-output', '@OUTPUT@',
      '@INPUT@',
    ],
  )
  generated_backend_sources += license_dev_pin
endif

backend_sources += license_sources

# subdir('test') is added with the TAP suite in work order step 6.
