<h1 align="center"> V2Ray Gen </h1>
<p> V2Ray Gen aiming at ease of use and configurability. <br>
V2Ray Gen are desigend for setting Up V2Ray-Core with Customized JSON Template on the server </p>

<h2>How To Use :</h2>
<h4>Quick Method with Default setting :</h4>

**VMess**
```
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | python3 - --vmess
# OR
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py --output V2RayGen.py
python3 V2RayGen.py --vmess
```
> for changing port simple use --port <int>

<h4>Advanced Method </h4>

```
curl https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/V2RayGen.py | python3 - --generate --protocol freedom --port 8080 --dns google --link
```
> above command will generate vmess json with freedom outband protocol , port 8080 , google dns and finaly generating vmess link

**Avaliable Options :**
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
