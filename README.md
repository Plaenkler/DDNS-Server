# 🌐 DDNS-Server

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Release](https://img.shields.io/badge/Calver-YY.WW.REVISION-22bfda.svg)](https://calver.org/)
[![Linters](https://github.com/Plaenkler/DDNS-Server/actions/workflows/linters.yml/badge.svg)](https://github.com/Plaenkler/DDNS-Server/actions/workflows/linters.yml)
[![Support me](https://img.shields.io/badge/Support%20me%20%E2%98%95-orange.svg)](https://www.buymeacoffee.com/Plaenkler)

With DDNS-Server you can setup your own dynamic DNS server. This project is an actively maintained enhancement of [docker-ddns-server](https://github.com/benjaminbear/docker-ddns-server).

<table>
  <tr>
    <td><img src="https://raw.githubusercontent.com/benjaminbear/docker-ddns-server/master/img/addhost.png" width="480"/></td>
    <td><img src="https://raw.githubusercontent.com/benjaminbear/docker-ddns-server/master/img/listhosts.png" width="480"/></td>
  </tr>
</table>

## Installation

You can either take the docker image or build it on your own.

### Using the docker image

Just customize this to your needs and run:

```
docker run -it -d \
    -p 8080:8080 \
    -p 53:53 \
    -p 53:53/udp \
    -v /somefolder:/var/cache/bind \
    -v /someotherfolder:/root/database \
    -e DDNS_ADMIN_LOGIN=admin:123455546. \
    -e DDNS_DOMAINS=dyndns.example.com \
    -e DDNS_PARENT_NS=ns.example.com \
    -e DDNS_DEFAULT_TTL=3600 \
    --name=dyndns \
    bbaerthlein/docker-ddns-server:latest
```

### Using docker-compose

You can also use Docker Compose to set up this project. For an example `docker-compose.yml`, please refer to this file: https://github.com/benjaminbear/docker-ddns-server/blob/master/deployment/docker-compose.yml

### Configuration

`DDNS_ADMIN_LOGIN` is a htpasswd username password combination used for the web ui. You can create one by using htpasswd:
```
htpasswd -nb user password
```
If you want to embed this into a docker-compose.yml you have to double the dollar signs for escaping:
```
echo $(htpasswd -nb user password) | sed -e s/\\$/\\$\\$/g
```
If `DDNS_ADMIN_LOGIN` is not set, all /admin routes are without protection. (use case: auth proxy)

`DDNS_DOMAINS` are the domains of the webservice and the domain zones of your dyndns server (see DNS Setup) i.e. `dyndns.example.com,dyndns.example.org` (comma separated list)

`DDNS_PARENT_NS` is the parent name server of your domain i.e. `ns.example.com`

`DDNS_DEFAULT_TTL` is the default TTL of your dyndns server.

`DDNS_CLEAR_LOG_INTERVAL` optional: clear log entries automatically in days (integer) e.g. `DDNS_CLEAR_LOG_INTERVAL:30`

`DDNS_ALLOW_WILDCARD` optional: allows all `*.subdomain.dyndns.example.com` to point to your ip (boolean) e.g. `true`

`DDNS_LOGOUT_URL` optional: allows a logout redirect to certain url by clicking the logout button (string) e.g. `https://example.com` 

### DNS setup

If your parent domain is `example.com` and you want your dyndns domain to be `dyndns.example.com`,
an example domain of your dyndns server would be `blog.dyndns.example.com`.

You have to add these entries to your parent dns server:
```
dyndns                   IN NS      ns
ns                       IN A       <put ipv4 of dns server here>
ns                       IN AAAA    <optional, put ipv6 of dns server here>
```

## Updating entry

After you have added a host via the web ui you can setup your router.
Example update URL:

```
http://dyndns.example.com:8080/update?hostname=blog.dyndns.example.com&myip=1.2.3.4
or
http://username:password@dyndns.example.com:8080/update?hostname=blog.dyndns.example.com&myip=1.2.3.4
```

this updates the host `blog.dyndns.example.com` with the IP 1.2.3.4. You have to setup basic authentication with the username and password from the web ui.

If your router doensn't support sending the ip address (OpenWRT) you don't have to set myip field:

```
http://dyndns.example.com:8080/update?hostname=blog.dyndns.example.com
or
http://username:password@dyndns.example.com:8080/update?hostname=blog.dyndns.example.com
```

The handler will also listen on:
* /nic/update
* /v2/update
* /v3/update
