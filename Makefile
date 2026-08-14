NAME := cfirewalld
BINARY := cfw-build
DOCKER := $(shell which podman 2>/dev/null || which docker)
CARGO_VERSION := $(shell grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
VERSION := v$(CARGO_VERSION)
GIT_DIRTY := $(shell git diff-index --quiet HEAD -- . 2>/dev/null || echo dirty)
GIT_TAG := $(shell git describe --exact-match --tags 2>/dev/null | grep -E '^cfirewalld-v')
GIT_VERSION := $(shell git log --oneline . | wc -l)-$(shell git rev-parse --short HEAD)
BASE_VERSION := $(if $(GIT_DIRTY),$(VERSION)+$(GIT_VERSION),$(if $(GIT_TAG),$(VERSION),$(VERSION)+$(GIT_VERSION)))
DEB_VERSION := $(patsubst v%,%,$(BASE_VERSION))
DEB_AMD64 := $(NAME)_$(DEB_VERSION)_amd64.deb
DEB_ARM64 := $(NAME)_$(DEB_VERSION)_arm64.deb
IMG := $(NAME)-build:$(subst +,-,$(BASE_VERSION))
PKG := target/package.tmp

# Files shared by every architecture's .deb.
DEB := packaging/DEBIAN
DEB_ASSETS := $(DEB)/control $(DEB)/postinst $(DEB)/prerm $(DEB)/postrm $(DEB)/conffiles \
              packaging/copyright systemd/cfirewalld.service \
              scripts/cfirewalld-start scripts/fw_reload-wrapper \
              fw_reload fw_vars $(wildcard subcommands/*) $(wildcard firewall.d/*.sh)

# $(1) = path to the cfw-build binary to install
# $(2) = sed expressions rewriting DEBIAN/control
define stage_pkg
	rm -rf "$(PKG)"
	install -D -m 755 -T "$(1)" "$(PKG)/usr/lib/$(NAME)/$(BINARY)"
	install -D -m 644 -T $(DEB)/control "$(PKG)/DEBIAN/control"
	install -D -m 644 -T $(DEB)/conffiles "$(PKG)/DEBIAN/conffiles"
	install -D -m 755 -T $(DEB)/postinst "$(PKG)/DEBIAN/postinst"
	install -D -m 755 -T $(DEB)/prerm "$(PKG)/DEBIAN/prerm"
	install -D -m 755 -T $(DEB)/postrm "$(PKG)/DEBIAN/postrm"
	sed -i $(2) "$(PKG)/DEBIAN/control"
	install -D -m 755 -T fw_reload "$(PKG)/usr/share/$(NAME)/fw_reload"
	install -d -m 755 "$(PKG)/usr/share/$(NAME)/subcommands"
	install -m 755 -t "$(PKG)/usr/share/$(NAME)/subcommands" subcommands/*
	install -D -m 755 -T scripts/fw_reload-wrapper "$(PKG)/usr/sbin/fw_reload"
	install -D -m 755 -T scripts/cfirewalld-start "$(PKG)/usr/sbin/cfirewalld-start"
	install -D -m 644 -T systemd/cfirewalld.service "$(PKG)/lib/systemd/system/cfirewalld.service"
	install -D -m 644 -T packaging/copyright "$(PKG)/usr/share/doc/$(NAME)/copyright"
	install -D -m 644 -T fw_vars "$(PKG)/etc/$(NAME)/fw_vars"
	install -d -m 755 "$(PKG)/etc/$(NAME)/firewall.d" "$(PKG)/etc/$(NAME)/post-run.d"
	install -m 644 -t "$(PKG)/etc/$(NAME)/firewall.d" firewall.d/*.sh
	install -d -m 755 "$(PKG)/var/lib/$(NAME)"
	# fw_reload and the subcommands are found through /etc, which is where an
	# operator looks; the payload lives under /usr/share.
	ln -s /usr/share/$(NAME)/subcommands "$(PKG)/etc/$(NAME)/subcommands"
	ln -s /usr/share/$(NAME)/fw_reload "$(PKG)/etc/$(NAME)/fw_reload"
endef

.PHONY: all clean binary deb deb-arm64 deb-all test

all: binary

binary: $(BINARY)

test:
	cargo test --release

deb: $(DEB_AMD64)

deb-arm64: $(DEB_ARM64)

deb-all: $(DEB_AMD64) $(DEB_ARM64)

$(DEB_AMD64): $(BINARY).amd64 $(DEB_ASSETS)
	$(call stage_pkg,$(BINARY).amd64,-e "s/^Version:.*/Version: $(DEB_VERSION)/" -e "s/^Architecture:.*/Architecture: amd64/")
	dpkg-deb --build --root-owner-group "$(PKG)" "$@"
	rm -rf "$(PKG)"

$(DEB_ARM64): $(BINARY).arm64 $(DEB_ASSETS)
	$(call stage_pkg,$(BINARY).arm64,-e "s/^Version:.*/Version: $(DEB_VERSION)/" -e "s/^Architecture:.*/Architecture: arm64/")
	dpkg-deb --build --root-owner-group "$(PKG)" "$@"
	rm -rf "$(PKG)"

# Built in a container so the build host needs no Rust toolchain, against
# bullseye so the result runs on Debian 11 and newer.
$(BINARY).amd64: Cargo.toml Cargo.lock Containerfile $(wildcard src/*.rs)
	./build-helper.sh x86_64

$(BINARY).arm64: Cargo.toml Cargo.lock Containerfile $(wildcard src/*.rs)
	./build-helper.sh aarch64

$(BINARY): $(BINARY).amd64
	cp $< $@

clean:
	rm -rf "$(PKG)" "$(BINARY)" "$(BINARY)".* *.deb
