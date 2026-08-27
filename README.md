# Secure WireGuard Tunnel

This repository contains an interactive installer for a **private, authenticated WireGuard tunnel between two Ubuntu hosts you administer**. It provides narrowly scoped TCP/UDP forwarding from an **Iran Server** (the public ingress host) to services running on a **Foreign Server**.

> **Scope and authorization:** Use this only for infrastructure that you own or are authorized to manage, and comply with applicable law, provider policies, and organizational change-control requirements. This project intentionally does **not** provide DPI evasion, protocol obfuscation, or guidance for circumventing third-party or government network controls.

WireGuard is used instead of GOST, Xray, or V2Ray because it is a widely supported, kernel-integrated VPN with authenticated encryption and low overhead on Ubuntu. It is appropriate for a conventional, secure site-to-site tunnel.

## What the installer does

- Supports **Ubuntu 20.04 and 22.04** only.
- Installs `wireguard`, `iptables`, and `iptables-persistent` when needed.
- Creates an authenticated `/30` WireGuard link using interface `wg0`.
- Enables IPv4 forwarding in `/etc/sysctl.d/99-secure-tunnel.conf`.
- On the Iran host, DNATs only the TCP/UDP public ports explicitly selected during setup to the Foreign host's WireGuard address.
- Masquerades only those DNATed tunnel flows, ensuring reply traffic traverses the tunnel.
- On the Foreign host, permits only explicitly selected service ports received from the WireGuard peer.
- Saves the managed firewall rules through `netfilter-persistent`, so they survive reboot.
- Stores non-secret deployment metadata in `/etc/secure-tunnel/manifest.conf` and supports status and clean removal.

The installer does **not** flush existing iptables rules or set generic `DROP` policies. It rejects an active UFW configuration rather than mixing UFW with `iptables-persistent`; decide on one firewall manager under your normal operations process. It also keeps the host's WireGuard private identity in `/etc/secure-tunnel/identity.key` (mode `0600`) so both public keys can be exchanged before either endpoint applies its tunnel configuration.

## Prerequisites

Before running the script:

1. Have root or `sudo` access to both servers.
2. Assign each server a stable, reachable public IPv4 address (or provide a suitable reachable endpoint/NAT mapping).
3. Choose an unused UDP port for WireGuard on **both** hosts, such as `51820`.
4. Allow the selected WireGuard UDP port through cloud security groups, upstream firewalls, and host firewalls on both servers.
5. On the Iran host only, allow the specific public service ports that you intend to expose. Do **not** open a wider range than necessary.
6. Know the Foreign service ports. Services on the Foreign host must listen on the Foreign host's WireGuard address or another non-loopback address; a service bound only to `127.0.0.1` will not accept these forwarded connections.

## Deployment order

WireGuard peers authenticate using public keys. The installer generates a unique key pair locally and never asks for or transmits a peer's private key. To exchange the public keys cleanly, use this order.

### 1. Place the files on both hosts

```bash
chmod 700 secure-tunnel.sh
sudo ./secure-tunnel.sh
```

If you copy the script from a workstation, first validate its checksum through your organization’s normal software-distribution process.

### 2. Initialize the Foreign Server

1. Choose **Install or update a managed tunnel**.
2. Select **Foreign Server**.
3. Enter the Iran server's reachable public IPv4 address.
4. Select the same WireGuard UDP port you will use at both ends.
5. Use the role defaults unless you have a documented reason to choose another `/30`:
   - Iran: `10.77.0.1`
   - Foreign: `10.77.0.2`
6. The script generates and displays the **Foreign public key before prompting for the peer key**. Copy it, then press **Enter** at the peer-key prompt. Its private identity remains safely stored at `/etc/secure-tunnel/identity.key` (mode `0600`) for the final configuration run.

### 3. Initialize the Iran Server

1. Run the installer and choose **Install or update**, then **Iran Server**.
2. Enter the Foreign server's reachable public IPv4 address and the same WireGuard UDP port.
3. Keep the complementary `/30` values (`10.77.0.1` local, `10.77.0.2` peer) unless using a documented alternative.
4. Copy the Iran public key displayed before the peer-key prompt, then press **Enter** at that prompt. As on Foreign, this preserves a local private identity without applying partial tunnel or firewall configuration.

### 4. Configure both servers with the verified peer key

Run the installer again on **each** server and choose its respective role. Enter the other server's public key, then select the matching allowed services:

- On **Iran**, add each public-to-Foreign mapping. For example, `tcp` public `443` to Foreign service `443` sends connections to `10.77.0.2:443`.
- On **Foreign**, add the corresponding `tcp` service port `443`, so only the authenticated Iran WireGuard peer can reach it.

Avoid using the WireGuard UDP port itself (for example UDP `51820`) as a public service-forwarding port.

> The connection can establish only after each endpoint has the other's real public key. Exchange public keys using an authenticated channel, such as your established administrative access or configuration-management system.

## Example topology

```text
Client
  |
  | TCP/443 to Iran public IP
  v
Iran Server (public ingress)              Foreign Server (service host)
public interface -> DNAT + MASQUERADE -> WireGuard wg0 -> 10.77.0.2:443
                    encrypted, authenticated tunnel
```

The Foreign host sees the forwarded source as the Iran host's WireGuard address. This is deliberate: it ensures the reply takes the tunnel back to the Iran host. This release forwards to services that run directly on the Foreign host; it does not route onward to arbitrary destination networks.

## Verify the deployment

Run these as root on both hosts after both peer keys are configured:

```bash
systemctl status wg-quick@wg0 --no-pager
wg show wg0
sysctl net.ipv4.ip_forward
```

A functioning tunnel shows both a peer entry and a recent `latest handshake` after traffic is generated. Test the private tunnel first:

```bash
# From Iran, test a known TCP service on Foreign.
nc -vz 10.77.0.2 443

# From an independent test client, test the public ingress on Iran.
nc -vz <IRAN_PUBLIC_IP> 443
```

For UDP, use an application-level test appropriate to the service because a UDP port scan alone does not prove end-to-end delivery. On the Iran host, inspect only the chains managed by this installer:

```bash
iptables -S SECURE_TUNNEL_INPUT
iptables -S SECURE_TUNNEL_FORWARD
iptables -t nat -S SECURE_TUNNEL_PRE
iptables -t nat -S SECURE_TUNNEL_POST
```

After a maintenance reboot, re-run `wg show wg0` and the same controlled connectivity tests. `wg-quick@wg0` and `netfilter-persistent` are enabled by the installer.

## Day-two operations

Run the installer again as root to display the lifecycle menu:

```bash
sudo ./secure-tunnel.sh
```

- **Install or update**: updates the local peer configuration and replaces only the dedicated managed iptables chains, avoiding duplicate rules.
- **Show status**: displays the non-secret manifest, interface status, forwarding sysctl value, and managed firewall chains.
- **Uninstall**: requires the exact confirmation word `REMOVE`, then removes only this script's WireGuard configuration, sysctl drop-in, manifest, and dedicated iptables chains. It does not globally flush firewall rules or force IPv4 forwarding off, because other authorized workloads might rely on it.

## Operational notes

- Keep UDP `51820` free of public port-forward mappings; reserve a different UDP port for an application if WireGuard uses 51820.
- The script assumes the Foreign destination service is hosted directly on the Foreign server. It does not create a default route or forward arbitrary Internet traffic through the Foreign server.
- Do not use the `203.0.113.10` prompt placeholder as an actual address. Replace it with the real, reachable peer endpoint.
- Keep `/etc/wireguard/wg0.conf` restricted: it contains the local private key and is created with mode `0600`.
- Review iptables, cloud-firewall, monitoring, logging, and incident-response controls according to your environment’s policy before exposing any production service.
