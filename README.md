# PIA WireGuard Config Generator

[![Docker Hub](https://img.shields.io/docker/pulls/spaceinvaderone/pia-wg-config-generator)](https://hub.docker.com/r/spaceinvaderone/pia-wg-config-generator)

A web-based tool for generating WireGuard configuration files for Private Internet Access VPN. While the configs work with any WireGuard client, this tool was specifically built to enable **custom Docker network routing on Unraid** - allowing individual containers to route all traffic through a VPN tunnel.

## Features

- Web-based interface with dark/light theme toggle
- Dynamic region-based config file naming (e.g., `PIA-us-east.conf`)
- Automatic Unraid tunnel naming support
- No credentials stored in the container
- Fetches live PIA server list
- Containerised single-image deployment (nginx + Flask)
- Works with any WireGuard client

## Quick Start

### Unraid Users

Search for **PIA WireGuard Config Generator** in Community Applications and install from there.

### Docker CLI

```bash
docker pull spaceinvaderone/pia-wg-config-generator:latest

docker run -d -p 8292:80 --name pia-wg-config-generator \
  spaceinvaderone/pia-wg-config-generator:latest
```

Access the web interface at `http://your-server-ip:8292`

## Usage

1. **Open the web interface** in your browser
2. **Enter your PIA credentials** (username and password)
3. **Select a region** - choose any region or one geographically close to you
4. **Generate and download** - the config file will download automatically
5. **Import the config** into your WireGuard client

The generated configuration file can be used with any WireGuard implementation.

## Unraid-Specific Setup

To use the generated config for custom Docker network routing on Unraid:

1. Generate and download a config file using the web interface
2. Go to **Settings → VPN Manager**
3. Click **Import Tunnel**
4. Select the downloaded `.conf` file
5. The tunnel will be automatically configured with the region name

Once imported, you can select this VPN tunnel as a custom network for any Docker container. All traffic from that container will be routed through the VPN.

## Use Case: Custom Docker Networks

The primary motivation for this project was to enable **per-container VPN routing** on Unraid. Rather than routing your entire server through a VPN, you can:

- Route specific containers (e.g., download clients, media apps) through the VPN
- Keep other containers (e.g., Plex, local services) using your regular network
- Use different VPN regions for different containers
- Maintain full network speed for non-VPN containers

This selective routing provides better performance and flexibility compared to system-wide VPN solutions.

## Requirements

- Docker or Unraid server
- [Private Internet Access](https://www.privateinternetaccess.com/pages/buy-vpn/spaceinvaderone) subscription (affiliate link)

## Video Tutorial

For a complete walkthrough of using this with Unraid Docker containers, visit the [SpaceInvaderOne YouTube channel](https://www.youtube.com/c/SpaceinvaderOne).

## Support

Found an issue or have a feature request? Please open an issue on the [GitHub repository](https://github.com/spaceinvaderone/pia-wg-config-generator).

## License

MIT License - see LICENSE file for details
