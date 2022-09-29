<h1 align="center"> V2Ray Gen

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![Telegram][telegram-shield]][telegram-url]
</h1>

## Introduction
<p> V2Ray Gen aiming at ease of use and configurability. <br>
V2Ray Gen are desigend for setting Up V2Ray-Core with Customized JSON Template on the Server. <br>
For now vmess are only supported option and it can be used to bypass Filtering and Censorship.
</p>

## Prerequisites & Dependencies
For running this project, you must have these dependencies installed and ready to use:

***docker***

***docker-compose***
 
***python3***

**or you can use --dockerup switch to install docker & docker-compose and run v2ray-core with script**

## How To Use

### Quick Method with Default Setting :

**VMess**
```bash
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | python3 - --vmess
# OR
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py --output V2RayGen.py
python3 V2RayGen.py --vmess
```
> for changing port simple use --port <int>

### Advanced Method :

```bash
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | python3 - --generate --protocol freedom --port 8080 --dns google --link
```
> above command will generate vmess json with freedom outband protocol , port 8080 , google dns and finaly generating vmess link

<br>
  
**Usage :**
 
```
--vmess, -s                           Generate simple vmess config and starting it with docker

VMess:
  --generate, --gen                   Generate vmess json config
  --link, --vmesslink                 Generate vmess link for v2ray config
  --linkname , --vmessname            Name for VMess Link. defualt: [v2ray]
  --protocol , --outband              Protcol for outband connection. default: [freedom]
  --port , -p                         Optional port for V2Ray Config. defualt: [80]
  --dns                               Optional dns. default: [nodns]

Docker:
  --dockerfile                        Generate docker-compose for v2ray
  --dockerup                          Start v2ray docker-compose in system
``` 
  > --dockerup will install docker and docker-compose if docker are not in the system


**Below DNS's can be used for JSON config**
|DNS's              |
|-------------------|
|google             |
|cloudflare         |
|opendns            |
|quad9              |
|adguard            |
 
**Supported Outband Protocols:**
|Outband            |
|-------------------|
|Freedom|           |
|BlackHole          |
|Freedom + BlackHole|


 
---
  
### Todo List

- [ ] ShadowSocks JSON Template
- [ ] Trojan JSON Template
- [ ] Adding more options for changing JSON values
- [ ] Catch Errors if Error Occured
- [ ] More Exception Error Handeling
- [ ] Add Verbose Mode With Logger


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/SonyaCore/V2RayGen?style=for-the-badge
[contributors-url]: https://github.com/SonyaCore/V2RayGen/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/SonyaCore/V2RayGen?style=for-the-badge
[forks-url]: https://github.com/SonyaCore/V2RayGen/network/members
[stars-shield]: https://img.shields.io/github/stars/SonyaCore/V2RayGen?style=for-the-badge
[stars-url]: https://github.com/SonyaCore/V2RayGen/stargazers
[issues-shield]: https://img.shields.io/github/issues/SonyaCore/V2RayGen?style=for-the-badge
[issues-url]: https://github.com/SonyaCore/V2RayGen/issues
[telegram-shield]: https://img.shields.io/badge/Telegram-blue.svg?style=for-the-badge&logo=telegram
[telegram-url]: https://t.me/ReiNotes
