<h1 align="center"> XRayGen

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![Telegram][telegram-shield]][telegram-url]

</h1>

<h3>
<strong>V2RayGen / XRayGen</strong> is a fully automated script that helps you to set up your own Xray server in the fastest time.
</h3>

[**Usage**](#usage)

[**Quick Setup**](#quicksetup)

[**Examples**](#examples)

[**Options ⚙️**](#options)

[**License 🪪**](#license)

[**Donate Me ☕**](#donateme)

## **Prerequisites & Dependencies**

For running this script, you must have **docker**, **docker-compose** and **python3** on your server **but** this script installs `docker` & `docker-compose` if your server doesn't have docker and runs xray-core automatically

use **sudo** if your current user is not in the docker group or you don't have docker installed

## **How XRayGen Works ?**

XRayGen uses docker to pull XRay image from the docker registry and after that, it generates a configuration file to start XRay container.

it also creates a client side configuration file so you can use that with xray-core or v2ray-core.

## **Usage**

`curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | python3 - -h`

![Sample](contents/content1.png)

<br>

## **QuickSetup**

You can use one of the following protocols for installation and change its settings according to your needs.

| Protoctol   | Argument            |
| ----------- | ------------------- |
| VMESS       | --vmess , -wm       |
| VMESS + TLS | --vmesstls , -vmtls |
| VLESS + TLS | --vless , -vl       |

### **Quick `Xray` Setup with Default Setting** :

```bash
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | sudo python3 - --vmess
```

OR

```bash
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py --output V2RayGen.py
sudo python3 V2RayGen.py --vmess
```

![Sample](contents/content3.png)

after installation use the provided link to your client or use the client-side json configuration with xray-core or v2ray-core

if your server is on the domain after importing the link to your v2ray client simply change the IP to your domain or subdomain

# **Examples**

**Setup XRAY / ShadowSocks :**

VLESS + TLS :

```bash
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | sudo python3 - --vless
```

VMESS + TLS with blocking option :

```bash
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | sudo python3 - --vmesstls --block
```

VMESS + Changing client-side HTTP and SOCKS port :

```bash
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | sudo python3 - --vmess --http 4020 --socks 8080
```

VLESS + Using Google DNS :

```bash
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | sudo python3 - --vless --dns google
```

ShadowSocks + adding shadowsocks port to server :

```bash
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | sudo python3 - --shadowsocks --firewall
```

**Parsing Configuration :**

Parse & reading Configuration file :

```bash
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | python3 - --parseconfig config.json
```

Parse URL and read information :

```bash
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | python3 -  --parse vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJhaWQiOiIwIiwiaG9zdCI6IiIsImlkIjoiM2JlNjE2NzktOGQzOC00ZWJiLWJjOGItMTQ4ZjE0ZWY5ZTc3IiwibmV0Ijoid3MiLCJwYXRoIjoiL2dyYXBocWwiLCJwb3J0IjoiNDQzIiwicHMiOiJ4cmF5IiwidGxzIjoidGxzIiwidHlwZSI6Im5vbmUiLCJ2IjoiMiIgfQ==
```

---

# **Options**

## Server Side

you can change server-side configuration with below options :

`linkname` for changing linkname after generating configuration.

`port` for changing configuration port.

`dns` for using custom dns instead system's default dns configuration.

`wspath` for changing default WebSocket path configuration.

`uuid` for using custom uuid configuration.

`id` custom alterID.

`loglevel` using another loglevel for configuration insted of [warning].

`header` for using custom header configuration.

`block` for adding blocking Bittorrent and Ads.

---

## Client Side

after generating the configuration with desired protocol client-side configuration is also generated as well

you can use client-side configuration directly with xray-core or v2ray-core

`security` security method for client-side configuration.

`socks` client-side SOCKS port . default: [2080]

`http` client-side HTTP port . default: [2081]

---

## Parsing Configuration

for parsing existed configuration or decoding vmess url use below options :

`parse` for parsing encoded link. supported formats are [vmess://,ss://]

`parseconfig` for reading the configuration file and parsing information

---

**Supported DNS providers:**

> use `--dns` to set one of below dns's.

| DNS        |
| ---------- |
| google     |
| cloudflare |
| opendns    |
| quad9      |
| adguard    |

> https://www.v2ray.com/en/configuration/dns.html

#### **Supported Outband Protocols:**

> use `--outband` to set one of below protocols.

| Outband Protocols   |
| ------------------- |
| Freedom             |
| BlackHole           |
| Freedom + BlackHole |

> https://www.v2ray.com/en/configuration/protocols.html

### **Custom JSON header**

#### `--header` argument are used for load custom header file

#### **Default Template for JSON HTTPRequest header**

> Visit below site for HTTPRequest Object :
> https://www.v2ray.com/en/configuration/transport/tcp.html#httprequestobject

> `Make sure your header file look like the below JSON` :

```
{
  "header": {
    "type": "http",
    "response": {
      "version": "1.1",
      "status": "200",
      "reason": "OK",
      "headers": {
        "Content-Type": [
          "application/octet-stream",
          "application/x-msdownload",
          "text/html",
          "application/x-shockwave-flash"
        ],
        "Transfer-Encoding": ["chunked"],
        "Connection": ["keep-alive"],
        "Pragma": "no-cache"
      }
    }
  }
}
```

## Link formats :

#### `VMess` :

```json
vmess://{"add":"ip / domain ","aid":"alterid","host":"","id":"random-uuid","net":"ws","path":"websocket-path","port":"80","ps":"linkname","tls":"","type":"none","v":"2" }
```

#### `VLess` :

```json
vless://random-uuid@ip:port?path=websocketpath&security=type&encryption=none&type=ws#linkname
```

#### `ShadowSocks` :

```json
ss://shadowsocks-security-method:random-uuid@domain/ip :port
```

## DonateMe

If this Project helped you, you can also help me by donation

### ![tron-button] &nbsp; TPFUnjJ4HNbGC6fp7WixFaAMBJ3ZLiUUio

### ![bitcoin-button] &nbsp; 1CVUoBRjDy1Thnaga6JKrnc83MAJzd5i4P

### ![ethereum-button] &nbsp; 0x199338177C2f6789cAd900A1534c76DA6669f12B

### ![tether-button] &nbsp; 0x199338177C2f6789cAd900A1534c76DA6669f12B

## License

Licensed under the [GPL-3][license] license.

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[tron-button]: https://img.shields.io/badge/Tron-ff69b4
[tether-button]: https://img.shields.io/badge/Tether-purple
[bitcoin-button]: https://img.shields.io/badge/Bitcoin-orange
[ethereum-button]: https://img.shields.io/badge/Ethereum-blue
[contributors-shield]: https://img.shields.io/github/contributors/SonyaCore/V2RayGen?style=flat
[contributors-url]: https://github.com/SonyaCore/V2RayGen/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/SonyaCore/V2RayGen?style=flat
[forks-url]: https://github.com/SonyaCore/V2RayGen/network/members
[stars-shield]: https://img.shields.io/github/stars/SonyaCore/V2RayGen?style=flat
[stars-url]: https://github.com/SonyaCore/V2RayGen/stargazers
[issues-shield]: https://img.shields.io/github/issues/SonyaCore/V2RayGen?style=flat
[issues-url]: https://github.com/SonyaCore/V2RayGen/issues
[telegram-shield]: https://img.shields.io/badge/Telegram-blue.svg?style=flat&logo=telegram
[telegram-url]: https://t.me/ReiNotes
[license]: LICENCE
