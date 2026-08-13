# Postgres Enterprise by AppsCode -- Alpine image.
#
# Adapted from docker-library/postgres 18/alpine3.23, with one change: instead
# of downloading the upstream release tarball, the source is supplied by the
# build context as postgresql-src.tar.gz (see build.sh), so the image is built
# from this fork -- REL_18_6 plus the single rebrand commit.
#
# The layout below (uid/gid 70, /usr/local prefix, PGDATA, VOLUME, entrypoint,
# STOPSIGNAL) is kept byte-for-byte compatible with the official image, so a
# downstream image such as kubedb/postgres-docker only needs its FROM line
# changed and its apk-based extension layer keeps working unmodified.

FROM alpine:3.23

# 70 is the standard uid/gid for "postgres" in Alpine
# https://git.alpinelinux.org/aports/tree/main/postgresql-common/postgresql-common.pre-install?h=3.22-stable
RUN set -eux; \
	addgroup -g 70 -S postgres; \
	adduser -u 70 -S -D -G postgres -H -h /var/lib/postgresql -s /bin/sh postgres; \
# also create the postgres user's home directory with appropriate permissions
# see https://github.com/docker-library/postgres/issues/274
	install --verbose --directory --owner postgres --group postgres --mode 1777 /var/lib/postgresql

# grab gosu for easy step-down from root
# https://github.com/tianon/gosu/releases
ENV GOSU_VERSION=1.19
RUN set -eux; \
	\
	apk add --no-cache --virtual .gosu-deps \
		ca-certificates \
		dpkg \
		gnupg \
	; \
	\
	dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')"; \
	wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch"; \
	wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc"; \
	\
# verify the signature
	export GNUPGHOME="$(mktemp -d)"; \
	gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4; \
	gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu; \
	gpgconf --kill all; \
	rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc; \
	\
# clean up fetch dependencies
	apk del --no-network .gosu-deps; \
	\
	chmod +x /usr/local/bin/gosu; \
# verify that the binary works
	gosu --version; \
	gosu nobody true

# make the "en_US.UTF-8" locale so postgres will be utf-8 enabled by default
# alpine doesn't require explicit locale-file generation
ENV LANG=en_US.utf8

RUN mkdir /docker-entrypoint-initdb.d

ENV PG_MAJOR=18
ENV PG_VERSION=18.6
# The product name this build reports from version(), pg_config --version, the
# --version flag of every binary, and the server startup log line.  The numeric
# version above is untouched, byte-for-byte identical to upstream 18.6.
ENV PG_PRODUCT_NAME="Postgres Enterprise by AppsCode"

ENV DOCKER_PG_LLVM_DEPS="llvm21-dev clang21"

# credcheck: credential policy enforcement (Bangladesh Bank ICT Security 8.2 /
# 5.9, Cybersecurity Framework 4.1.2).  Pinned to the commit behind tag v5.0
# rather than the tag itself, since a tag can be moved.
ENV CREDCHECK_VERSION=v5.0
ENV CREDCHECK_COMMIT=9a101e8e8de2ea3b7e1dfabed6568891e194acaf

# Source tarball produced by build.sh via "git archive" of the appscode/18
# branch.  Extracted rather than downloaded so the image is built from this
# fork; there is no upstream tarball to checksum.
COPY postgresql-src.tar.gz /usr/src/postgresql-src.tar.gz

RUN set -eux; \
	\
	mkdir -p /usr/src/postgresql; \
	tar \
		--extract \
		--file /usr/src/postgresql-src.tar.gz \
		--directory /usr/src/postgresql \
	; \
	rm /usr/src/postgresql-src.tar.gz; \
	\
	apk add --no-cache --virtual .build-deps \
		$DOCKER_PG_LLVM_DEPS \
		bison \
		coreutils \
		dpkg-dev dpkg \
		flex \
		g++ \
		gcc \
# to fetch credcheck at a pinned commit
		git \
		krb5-dev \
		libc-dev \
		libedit-dev \
		libxml2-dev \
		libxslt-dev \
		linux-headers \
		make \
		openldap-dev \
		openssl-dev \
		perl-dev \
		perl-ipc-run \
		perl-utils \
		python3-dev \
		tcl-dev \
		util-linux-dev \
		zlib-dev \
# https://www.postgresql.org/docs/10/static/release-10.html#id-1.11.6.9.5.13
		icu-dev \
# https://www.postgresql.org/docs/14/release-14.html#id-1.11.6.5.5.3.7
		lz4-dev \
# https://www.postgresql.org/docs/15/release-15.html "--with-zstd to enable Zstandard builds"
		zstd-dev \
# https://www.postgresql.org/docs/18/install-make.html#CONFIGURE-OPTION-WITH-LIBCURL
		curl-dev \
# https://www.postgresql.org/docs/18/install-make.html#CONFIGURE-OPTION-WITH-LIBURING
		liburing-dev \
	; \
	\
	cd /usr/src/postgresql; \
# update "DEFAULT_PGSOCKET_DIR" to "/var/run/postgresql" (matching Debian)
# see https://anonscm.debian.org/git/pkg-postgresql/postgresql.git/tree/debian/patches/51-default-sockets-in-var.patch?id=8b539fcb3e093a521c095e70bdfa76887217b89f
	awk '$1 == "#define" && $2 == "DEFAULT_PGSOCKET_DIR" && $3 == "\"/tmp\"" { $3 = "\"/var/run/postgresql\""; print; next } { print }' src/include/pg_config_manual.h > src/include/pg_config_manual.h.new; \
	grep '/var/run/postgresql' src/include/pg_config_manual.h.new; \
	mv src/include/pg_config_manual.h.new src/include/pg_config_manual.h; \
	gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \
	\
# https://git.alpinelinux.org/aports/tree/community/postgresql15/APKBUILD?h=3.22-stable#n176 ("export LLVM_CONFIG")
	export LLVM_CONFIG="/usr/lib/llvm21/bin/llvm-config"; \
# https://git.alpinelinux.org/aports/tree/community/postgresql15/APKBUILD?h=3.22-stable#n180 ("older clang versions don't have a 'clang' exe anymore.")
	export CLANG=clang-21; \
	\
# configure options mostly copying Debian:
# https://salsa.debian.org/postgresql/postgresql-common/-/blob/6e26b5107295170cc8731a3acbf13228ea15941e/server/postgresql.mk#L32
#
# NOTE: deliberately no --with-extra-version here.  That flag appends to
# PG_VERSION itself (making it "18.6-something"); the rebrand replaces only the
# product name and must leave the numeric version alone.
	./configure \
		--enable-option-checking=fatal \
		--build="$gnuArch" \
# "/usr/src/postgresql/src/backend/access/common/tupconvert.c:105: undefined reference to `libintl_gettext'"
#		--enable-nls \
		--enable-integer-datetimes \
		--enable-tap-tests \
# skip debugging info -- we want tiny size instead
#		--enable-debug \
		--disable-rpath \
		--with-uuid=e2fs \
		--with-pgport=5432 \
		--with-system-tzdata=/usr/share/zoneinfo \
		--prefix=/usr/local \
		--with-includes=/usr/local/include \
		--with-libraries=/usr/local/lib \
		--with-gssapi \
		--with-icu \
		--with-ldap \
		--with-libcurl \
		--with-liburing \
		--with-libxml \
		--with-libxslt \
		--with-llvm \
		--with-lz4 \
		--with-openssl \
#		--with-pam \
		--with-perl \
		--with-python \
		--with-tcl \
		--with-zstd \
	; \
	make -j "$(nproc)" world-bin; \
	make install-world-bin; \
	make -C contrib install; \
	\
# credcheck, built with PGXS against the Postgres just installed above.  Done
# inside this same RUN so it can use .build-deps, and before the scanelf sweep
# below so credcheck.so's shared-library needs are captured in runDeps.
#
# The optional cracklib dictionary check stays disabled (its CPPFLAGS/SHLIB_LINK
# are commented out upstream); enabling it would require provisioning cracklib
# and a dictionary in this image.
	git clone --no-checkout https://github.com/HexaCluster/credcheck.git /usr/src/credcheck; \
	git -C /usr/src/credcheck checkout --quiet "$CREDCHECK_COMMIT"; \
	git -C /usr/src/credcheck describe --tags --exact-match | grep -Fx "$CREDCHECK_VERSION"; \
	make -C /usr/src/credcheck -j "$(nproc)" USE_PGXS=1 PG_CONFIG=/usr/local/bin/pg_config; \
	make -C /usr/src/credcheck USE_PGXS=1 PG_CONFIG=/usr/local/bin/pg_config install; \
	test -f /usr/local/lib/postgresql/credcheck.so; \
	test -f /usr/local/share/postgresql/extension/credcheck.control; \
	\
	runDeps="$( \
		scanelf --needed --nobanner --format '%n#p' --recursive /usr/local \
			| tr ',' '\n' \
			| sort -u \
			| awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
# Remove plperl, plpython and pltcl dependencies by default to save image size
# To use the pl extensions, those have to be installed in a derived image
			| grep -v -e perl -e python -e tcl \
	)"; \
	apk add --no-cache --virtual .postgresql-rundeps \
		$runDeps \
		bash \
		tzdata \
		zstd \
# https://wiki.alpinelinux.org/wiki/Release_Notes_for_Alpine_3.16.0#ICU_data_split
		icu-data-full \
# https://git.alpinelinux.org/aports/tree/community/nss_wrapper/APKBUILD?h=3.22-stable#n7 ("ppc64le: test case segfaults")
		$([ "$(apk --print-arch)" != 'ppc64le' ] && echo 'nss_wrapper') \
	; \
	apk del --no-network .build-deps; \
	cd /; \
	rm -rf \
		/usr/src/postgresql \
		/usr/src/credcheck \
		/usr/local/share/doc \
		/usr/local/share/man \
	; \
	\
# Build-time assertion that the rebrand actually landed, and that it did not
# disturb the numeric version.  A silent fallback to stock branding here would
# otherwise only be caught downstream.
	postgres --version; \
	postgres --version | grep -F "postgres ($PG_PRODUCT_NAME) $PG_VERSION"; \
	pg_config --version | grep -Fx "$PG_PRODUCT_NAME $PG_VERSION"

# make the sample config easier to munge (and "correct by default")
RUN set -eux; \
	cp -v /usr/local/share/postgresql/postgresql.conf.sample /usr/local/share/postgresql/postgresql.conf.sample.orig; \
	sed -ri "s!^#?(listen_addresses)\s*=\s*\S+.*!\1 = '*'!" /usr/local/share/postgresql/postgresql.conf.sample; \
	grep -F "listen_addresses = '*'" /usr/local/share/postgresql/postgresql.conf.sample

# Credential policy, applied to every cluster initdb'd from this image.
#
# It goes in an include_dir rather than straight into postgresql.conf.sample so
# a deployment can override individual settings by mounting a later-sorting
# file into /etc/postgresql/conf.d without editing anything shipped here.
#
# NOTE: initdb copies the sample into a NEW data directory, so this reaches new
# clusters only.  A pre-existing PGDATA carried over from an older image keeps
# its own postgresql.conf and will NOT gain the include line or the policy; add
# the include there by hand when upgrading such a volume in place.
COPY conf.d/ /etc/postgresql/conf.d/
RUN set -eux; \
	printf '\n# AppsCode: credential policy, see /etc/postgresql/conf.d\ninclude_dir = %s\n' \
		"'/etc/postgresql/conf.d'" \
		>> /usr/local/share/postgresql/postgresql.conf.sample; \
	grep -F "include_dir = '/etc/postgresql/conf.d'" /usr/local/share/postgresql/postgresql.conf.sample; \
	test -f /etc/postgresql/conf.d/10-bb-ict-security.conf

# CREATE EXTENSION credcheck on first initialisation, for the admin views.
COPY initdb.d/ /docker-entrypoint-initdb.d/

RUN install --verbose --directory --owner postgres --group postgres --mode 3777 /var/run/postgresql

#
# NOTE: in 18+, PGDATA has changed to match the pg_ctlcluster standard directory structure, and the VOLUME has moved from /var/lib/postgresql/data to /var/lib/postgresql
#
ENV PGDATA=/var/lib/postgresql/18/docker
VOLUME /var/lib/postgresql
# ("/var/lib/postgresql" is already pre-created with suitably usable permissions above)

COPY docker-entrypoint.sh docker-ensure-initdb.sh /usr/local/bin/
RUN ln -sT docker-ensure-initdb.sh /usr/local/bin/docker-enforce-initdb.sh
ENTRYPOINT ["docker-entrypoint.sh"]

# We set the default STOPSIGNAL to SIGINT, which corresponds to what PostgreSQL
# calls "Fast Shutdown mode" wherein new connections are disallowed and any
# in-progress transactions are aborted, allowing PostgreSQL to stop cleanly and
# flush tables to disk.
#
# See https://www.postgresql.org/docs/current/server-shutdown.html for more details
# about available PostgreSQL server shutdown signals.
#
# See also https://www.postgresql.org/docs/current/server-start.html for further
# justification of this as the default value, namely that the example (and
# shipped) systemd service files use the "Fast Shutdown mode" for service
# termination.
#
STOPSIGNAL SIGINT
#
# An additional setting that is recommended for all users regardless of this
# value is the runtime "--stop-timeout" (or your orchestrator/runtime's
# equivalent) for controlling how long to wait between sending the defined
# STOPSIGNAL and sending SIGKILL.
#
# The default in most runtimes (such as Docker) is 10 seconds, and the
# documentation at https://www.postgresql.org/docs/current/server-start.html notes
# that even 90 seconds may not be long enough in many instances.

EXPOSE 5432
CMD ["postgres"]
