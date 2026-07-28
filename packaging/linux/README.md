# Linux deployment

## Install

```sh
make VERSION=1.0.0
sudo make install VERSION=1.0.0 GO="$(command -v go)"
sudo install -m 0644 packaging/linux/hub-net-node.default /etc/default/hub-net-node
sudo systemd-sysusers /usr/lib/sysusers.d/hub-net-node.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/hub-net-node.conf
sudo systemctl daemon-reload
sudo systemctl enable --now hub-net-node
curl --fail http://127.0.0.1:1964/healthz
```

Set unique `HUB_NET_NODE_ID` and desired bind address in
`/etc/default/hub-net-node`. Allow inbound TCP and UDP 1964, or selected port, through
host and cloud firewalls. Put TLS reverse proxy in front for public deployment.

## Upgrade

Build or unpack new release, stop service, replace `/usr/bin/hub-net-node`,
then start service. State format is currently empty; preserve
`/var/lib/hub-net-node` for forward compatibility.

```sh
sudo systemctl stop hub-net-node
sudo install -m 0755 build/hub-net-node /usr/bin/hub-net-node
sudo systemctl start hub-net-node
```

## Uninstall

```sh
sudo systemctl disable --now hub-net-node
sudo rm /usr/bin/hub-net-node \
  /usr/lib/systemd/system/hub-net-node.service \
  /usr/lib/sysusers.d/hub-net-node.conf \
  /usr/lib/tmpfiles.d/hub-net-node.conf \
  /etc/default/hub-net-node
sudo systemctl daemon-reload
```

State stays in `/var/lib/hub-net-node`. Remove it separately only when node
identity and all future retained state should be permanently deleted.

SIGTERM triggers graceful HTTP shutdown. Service needs no Linux capabilities:
node handles coordination traffic only and never creates WireGuard interfaces.
