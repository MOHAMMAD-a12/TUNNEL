# Secure WireGuard Tunnel

An interactive installer for a **private, authenticated WireGuard tunnel between two Ubuntu servers you administer**. It forwards only explicitly selected TCP/UDP ports from the **Iran Server** (public ingress) to services hosted directly on the **Foreign Server**.

> **Authorized-use boundary:** Use this only on infrastructure you own or are authorized to manage, in accordance with applicable law, provider policies, and organizational change-control requirements. This project does not implement DPI evasion, protocol obfuscation, or circumvention of third-party or government network controls.

WireGuard is a kernel-integrated VPN with authenticated encryption and low overhead. This installer intentionally limits its scope to an authorized, conventional service-forwarding tunnel—there is no default route, arbitrary egress forwarding, or generic proxy behavior.

## Quick Start

The installer supports **Ubuntu 20.04, 22.04, and 24.04**. Run it as root on **both** servers.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MOHAMMAD-a12/TUNNEL/main/secure-tunnel.sh)
```

Alternatively, download, inspect, and run a local copy:

```bash
curl -fLO https://raw.githubusercontent.com/MOHAMMAD-a12/TUNNEL/main/secure-tunnel.sh
chmod 700 secure-tunnel.sh
sudo ./secure-tunnel.sh
```

Before using either command, review the script under your organization’s software-distribution and change-control process. If your policy requires it, pin a reviewed commit instead of using `main`:

```bash
# Replace <COMMIT_SHA> with a reviewed commit identifier.
curl -fLO https://raw.githubusercontent.com/MOHAMMAD-a12/TUNNEL/<COMMIT_SHA>/secure-tunnel.sh
chmod 700 secure-tunnel.sh
sudo ./secure-tunnel.sh
```

During setup, the script displays a local WireGuard public key and asks for the other server’s public key. It stores the local private identity at `/etc/secure-tunnel/identity.key` with mode `0600`; it never requests, displays, or transfers a peer private key.

After initial setup, run the command again to open the lifecycle menu:

```bash
sudo ./secure-tunnel.sh
```

The menu provides these actions:

- **Install or update a managed tunnel** — configures WireGuard and the dedicated firewall chains.
- **Show status** — displays non-secret deployment metadata, interface state, forwarding state, and managed rules.
- **Uninstall this managed tunnel** — removes only installer-managed configuration after typed `REMOVE` confirmation.

## Deployment Prerequisites

Before installation:

1. Have root or `sudo` access to both Ubuntu servers.
2. Assign both servers stable, reachable public IPv4 addresses, or provide suitable reachable NAT mappings.
3. Choose an unused WireGuard UDP port on both hosts; `51820` is the default.
4. Allow that WireGuard UDP port through cloud security groups, upstream firewalls, and host firewalls on both servers.
5. On the Iran host, permit only the public TCP/UDP ports you intend to forward.
6. Ensure services on the Foreign host listen on its WireGuard address or another non-loopback address. A service listening only on `127.0.0.1` cannot receive the forwarded connection.
7. Do not use the example prompt value `203.0.113.10`; enter the real, reachable peer endpoint.

## Installation Workflow

WireGuard peers authenticate with public keys. Install in four steps to exchange those keys without applying a partial tunnel configuration.

### 1. Initialize the Foreign Server

1. Run the installer and choose **Install or update a managed tunnel**.
2. Select **Foreign Server**.
3. Enter the Iran server’s reachable public IPv4 address.
4. Choose the WireGuard UDP port. It must match the port configured on Iran.
5. Use the default tunnel addresses unless another documented `/30` is required:
   - Iran: `10.77.0.1`
   - Foreign: `10.77.0.2`
6. Copy the displayed **Foreign public key**, then press **Enter** at the peer-key prompt.

The script stores the Foreign private identity locally and exits without creating `wg0.conf`, enabling forwarding, or applying firewall changes.

### 2. Initialize the Iran Server

1. Run the installer and choose **Install or update a managed tunnel**.
2. Select **Iran Server**.
3. Enter the Foreign server’s reachable public IPv4 address and the same WireGuard UDP port.
4. Keep `10.77.0.1` as the Iran address and `10.77.0.2` as its peer unless using a documented alternative.
5. Copy the displayed **Iran public key**, then press **Enter** at the peer-key prompt.

### 3. Configure Iran With the Foreign Public Key

1. Run the installer again on Iran and select **Iran Server**.
2. Enter the Foreign public key collected in step 1.
3. Add each public-to-Foreign mapping:
   - Protocol: `tcp` or `udp`
   - Public port: the port exposed on Iran
   - Foreign service port: the corresponding service port on Foreign

For example, mapping TCP port `443` to Foreign port `443` sends connections from `IRAN_PUBLIC_IP:443` to `10.77.0.2:443` through WireGuard.

> The installer rejects a UDP forward mapping that collides with its WireGuard listener port—for example, UDP `51820` when WireGuard uses port `51820`.

### 4. Configure Foreign With the Iran Public Key

1. Run the installer again on Foreign and select **Foreign Server**.
2. Enter the Iran public key collected in step 2.
3. Add the matching protocol and service ports configured as destinations on Iran.

For the TCP/443 example, authorize `tcp` port `443` on Foreign. The installer permits that port only from the authenticated Iran WireGuard peer.

Exchange public keys through an authenticated administrative channel or your configuration-management system. Do not share private keys.

## Example Topology

```text
Client
  |
  | TCP/443 to Iran public IP
  v
Iran Server (public ingress)              Foreign Server (service host)
public interface -> DNAT + MASQUERADE -> WireGuard wg0 -> 10.77.0.2:443
                    encrypted, authenticated tunnel
```

The Foreign host receives the forwarded source as Iran’s WireGuard address. This deliberate source NAT ensures response traffic returns across the authenticated tunnel. The installer forwards only to services running directly on the Foreign server; it does not route onward to arbitrary destination networks.

## What the Installer Configures

- `wireguard`, `iptables`, and `iptables-persistent` when their required commands are absent.
- A WireGuard `/30` interface on `wg0` with one authenticated peer and `PersistentKeepalive = 25`.
- IPv4 forwarding using `/etc/sysctl.d/99-secure-tunnel.conf`.
- On Iran: dedicated `iptables` DNAT, forward, return-path, and scoped masquerade rules for selected public mappings.
- On Foreign: dedicated `iptables` rules that allow only selected service ports from the Iran tunnel peer.
- Firewall persistence via `netfilter-persistent`.
- Non-secret deployment state in `/etc/secure-tunnel/manifest.conf` with mode `0600`.

The installer does **not** flush existing iptables rules, change generic firewall policies, or use `0.0.0.0/0` as a WireGuard peer route. It refuses to run when UFW is active to avoid mixing UFW with `iptables-persistent`. It also refuses to overwrite an existing `wg0.conf` that is not installer-managed.

## Verify the Deployment

After both endpoints are configured, run these commands as root on both servers:

```bash
systemctl status wg-quick@wg0 --no-pager
wg show wg0
sysctl net.ipv4.ip_forward
```

A working tunnel shows a peer and a recent `latest handshake` after traffic is generated. Test the private service path first:

```bash
# On Iran: test a known TCP service hosted by Foreign.
nc -vz 10.77.0.2 443

# From an independent client: test Iran’s public forwarding port.
nc -vz <IRAN_PUBLIC_IP> 443
```

For UDP, use an application-level check appropriate to the service; a UDP port scan does not establish end-to-end delivery.

On Iran, inspect only the chains created by this installer:

```bash
iptables -S SECURE_TUNNEL_INPUT
iptables -S SECURE_TUNNEL_FORWARD
iptables -t nat -S SECURE_TUNNEL_PRE
iptables -t nat -S SECURE_TUNNEL_POST
```

After a maintenance reboot, repeat `wg show wg0` and the controlled service checks. The installer enables both `wg-quick@wg0` and `netfilter-persistent`.

## Updates and Removal

### Update an existing deployment

Run the installer, select **Install or update**, and re-enter the local role, peer details, and desired mappings. It rebuilds only its dedicated firewall chains, avoiding duplicate installer-managed rules.

### Remove the managed deployment

Run the installer, select **Uninstall this managed tunnel**, and type `REMOVE` when prompted. The installer removes only:

- `/etc/wireguard/wg0.conf`
- `/etc/sysctl.d/99-secure-tunnel.conf`
- `/etc/secure-tunnel/manifest.conf`
- `/etc/secure-tunnel/identity.key`
- Dedicated `SECURE_TUNNEL_*` `iptables` chains and hooks

It does not globally flush firewall rules or force IPv4 forwarding off, because another authorized workload may depend on the host’s current setting.

## Operational Notes

- Keep the WireGuard UDP port free of public forwarding mappings.
- Keep `/etc/wireguard/wg0.conf` restricted: it contains the local private key and is written with mode `0600`.
- Review firewall policy, cloud firewall rules, monitoring, logging, and incident-response controls before exposing a production service.
- Validate behavior in disposable Ubuntu 20.04, 22.04, and 24.04 environments before production deployment.
