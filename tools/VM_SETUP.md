# The test machine

A Linux virtual machine is the easiest way to try the TUN client, because
`/dev/net/tun` is part of the Linux kernel and needs no driver.

This is how the test machine of this project was built.  It is not needed to
use the project, it is only here so the setup can be repeated.

## What was used

* VMware Workstation 17
* the Ubuntu cloud image (24.04 LTS, server, amd64) from
  <https://cloud-images.ubuntu.com/noble/current/> - the `.ova` file is
  directly importable into VMware
* a cloud-init seed ISO with the SSH key and the packages
* the project itself, copied over with `scp`

## 1. Import the image

```bash
OVFTOOL="C:/Program Files (x86)/VMware/VMware Workstation/OVFTool/ovftool.exe"
"$OVFTOOL" --acceptAllEulas --noSSLVerify \
  ubuntu-noble-cloudimg-amd64.ova \
  "$HOME/Documents/Virtual Machines/ti-vm/ti-vm.vmx"
```

## 2. Make the seed ISO

The first boot of a cloud image takes its configuration from a small ISO
with the label `cidata`:

```yaml
# user-data
#cloud-config
users:
  - name: ubuntu
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - ssh-ed25519 AAAA... the public key
ssh_pwauth: false
package_update: true
packages:
  - python3
  - python3-venv
  - iptables
runcmd:
  - [ sh, -c, "modprobe tun || true" ]
  - [ sh, -c, "python3 -m venv /opt/ti-venv" ]
  - [ sh, -c, "/opt/ti-venv/bin/pip install pycryptodome" ]
  - [ sh, -c, "mkdir -p /opt/traffic-inspector" ]
```

```
# meta-data
instance-id: traffic-inspector-vm-01
local-hostname: ti-vm
```

```bash
python tools/make_seed_iso.py user-data meta-data seed.iso
```

## 3. Point the machine at the seed and switch the firmware

In the `.vmx` of the machine:

```
ide1:0.fileName = "C:\...\seed.iso"
ide1:0.deviceType = "cdrom-image"
ide1:0.startConnected = "TRUE"
firmware = "efi"          # the cloud image boots with UEFI
ethernet0.connectionType = "nat"
memsize = "2048"
```

**Edit the `.vmx` while the machine is stopped.**  VMware rewrites the file
when the machine shuts down and would undo the change.

## 4. Boot and log in

```bash
vmrun start ti-vm.vmx nogui
vmrun getGuestIPAddress ti-vm.vmx -wait
ssh -i id_ed25519 ubuntu@<ip>
```

The key pair is made with `ssh-keygen -t ed25519 -f id_ed25519`.

## 5. The server next to the client

When the server runs on the same machine as the TUN client, the traffic of
the server would go into the tunnel as well and the machine would chase its
own tail.  `tools/ti-routes.sh` sends the traffic of the server through a
table of its own:

```bash
sudo ./ti-routes.sh ens192
```

The server also has to be told which address to use, so that the flows it
opens leave with the right source address:

```bash
python listeningServer.py --host <the address of the machine> --port 5555
```

## 6. Run it

```bash
# the server
python listeningServer.py --host 192.168.142.133 --port 5555 --csv traffic.csv

# the client, it needs root for the interface and the routes
sudo python -m client.main --server 192.168.142.133 --port 5555 \
     --tun ti0 --address 10.8.0.1/24 --dns 8.8.8.8
```

Then browse in the machine and watch `traffic.csv`.
