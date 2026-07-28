PREFIX ?= /usr
DESTDIR ?=
VERSION ?= dev
GO ?= go
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)

.PHONY: all build test fuzz security load integration-linux integration-two-nat integration-nat-matrix package checksums release-gate install

all: build

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath \
		-ldflags="-s -w -X github.com/v57/hub-net-node/version.Build=$(VERSION)" \
		-o build/hub-net-node ./cmd/hub-net-node

test:
	$(GO) test -race ./...
	$(GO) vet ./...

fuzz:
	$(GO) test ./transport/ws -run '^$$' -fuzz FuzzReadFrame -fuzztime 30s

security:
	govulncheck ./...

load:
	$(GO) test ./server -run 'TestAdmissionListenerBoundsIncompleteConnections|TestProcessSurvivesMalformedFrames' -count=1

integration-linux:
	./integration/linux_acceptance.sh

integration-two-nat:
	./integration/two_nat_no_relay.sh

integration-nat-matrix:
	./integration/nat_matrix.sh

package: build
	rm -rf "build/package"
	mkdir -p "build/package/hub-net-node-$(VERSION)-$(GOOS)-$(GOARCH)"
	cp build/hub-net-node README.md LICENSE "build/package/hub-net-node-$(VERSION)-$(GOOS)-$(GOARCH)/"
	cp -R packaging/linux "build/package/hub-net-node-$(VERSION)-$(GOOS)-$(GOARCH)/packaging"
	tar -C build/package -czf "build/hub-net-node-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz" \
		"hub-net-node-$(VERSION)-$(GOOS)-$(GOARCH)"

checksums:
	cd build && sha256sum hub-net-node-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz > \
		hub-net-node-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz.sha256

release-gate: test load security integration-linux

install: build
	install -d -m 0755 "$(DESTDIR)$(PREFIX)/bin"
	install -d -m 0755 "$(DESTDIR)$(PREFIX)/lib/systemd/system"
	install -d -m 0755 "$(DESTDIR)$(PREFIX)/lib/sysusers.d"
	install -d -m 0755 "$(DESTDIR)$(PREFIX)/lib/tmpfiles.d"
	install -m 0755 build/hub-net-node "$(DESTDIR)$(PREFIX)/bin/hub-net-node"
	install -m 0644 packaging/linux/hub-net-node.service "$(DESTDIR)$(PREFIX)/lib/systemd/system/hub-net-node.service"
	install -m 0644 packaging/linux/hub-net-node.sysusers "$(DESTDIR)$(PREFIX)/lib/sysusers.d/hub-net-node.conf"
	install -m 0644 packaging/linux/hub-net-node.tmpfiles "$(DESTDIR)$(PREFIX)/lib/tmpfiles.d/hub-net-node.conf"
