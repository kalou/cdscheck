# CDS/CDNSKEY/DNSKEY record checker

## Basic usage
Usage: ./cdscheck -config /path/to/trust/dir

Trust dir might contain files with the following:

```bind
.                       45754   IN      DNSKEY  257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF 
                                                        FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX
                                                        bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD
                                                        X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz
                                                        W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS
                                                        Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq
                                                        QxA+Uk1ihz0=

.                       350902  IN      NS      e.root-servers.net.
.                       350902  IN      NS      l.root-servers.net.
.                       350902  IN      NS      c.root-servers.net.
.                       350902  IN      NS      k.root-servers.net.
.                       350902  IN      NS      f.root-servers.net.
.                       350902  IN      NS      b.root-servers.net.
.                       350902  IN      NS      d.root-servers.net.
.                       350902  IN      NS      g.root-servers.net.
.                       350902  IN      NS      h.root-servers.net.
.                       350902  IN      NS      j.root-servers.net.
.                       350902  IN      NS      m.root-servers.net.
.                       350902  IN      NS      i.root-servers.net.
.                       350902  IN      NS      a.root-servers.net.
```

DNSKEY records (with any given name) are used as trust anchors - and reported in the "delegation" attribute below. That allows one to take action based on the trusted key.

NS records for "." are added to the hints for lookups.

## Motivation
Having a programmatically accessible service to play with DNSSEC records will allow for more flexibility in various validation functions.

Simply using a validating, caching nameserver often results in valid - but incomplete dnssec information. ANY might return incomplete results, making it difficult to work with the zone data.

A CDS/CDNSKEY service might benefit from the short-lived caching and "immediate" access to domain data. It might make sense to extend this service to other TXT-based validations, or anything requiring direct access to any domain data.

The use of Go for parallel servicing of many http/DNS-requests seems OK, and miekg/dns has a very up-to-date, easy to use API requiring no addition to support CDS/CDNSKEY and manual DNSSEC validation.

## Usage
Only one basic URL as of now:

```http
GET /domain/debian.org
```

Should result in the following kind of structure:

```json
{"delegation":["."],"DNSKEY":[{"Hdr":{"Name":"debian.org.","Rrtype":48,"Class":1,"Ttl":28800,"Rdlength":264},"Flags":257,"Protocol":3,"Algorithm":8,"PublicKey":"AwEAAaT+6cg2b9/MI/Z50Zt1+DrvT0Y8+CZaeQLztiWADmij9kjRWq1cXPmJgLgCQ4GoXfIQcN9yLDL6WT+W5zPt8nyKLFWFXayRhLpbqgzZHdzHy54BMKxu1xzY+NxRK3aAcNT+R1B2u2URQ8iH+Qxm04MQHLomwoSULWqghFf7kIXt0KeJN7TInQtPFLBkK0mcOqVDEieKgjeLH5FQ+5wfFLJ0jWZgkC4YlSrjdu33Gsh3g7qOI56nbF7MCo+FtNqT7AHIrEql1Y+EykqiVOtYLnXbuHpCfNhBY/2OVtXtUYHmWIzlXAxMvpvQRpzlOplIzKx67LAYNDK77UZ+X2mb3u0="},{"Hdr":{"Name":"debian.org.","Rrtype":48,"Class":1,"Ttl":28800,"Rdlength":200},"Flags":256,"Protocol":3,"Algorithm":8,"PublicKey":"AwEAAbprC+KFLWurNL2MvrJDwmc95k4yqZVXd7YweMcaoEVgLE+PRT3PCix3j0XNOK8XqkR7K1FeSfMzUFLcNzHxj87GNOdqutUrFS9QyVLST2tfwKi/LZTpWUNliWDKmiU+TOQ2KdYpubKlgWCOn8HVp/sTH2sBQrmAlV37inpDAmSSZwEflT4kW3fusH7thsb9SNzJLqHSwCe1Yf2OskLl2qkwxmE2pyBGESHKYCvk93Ah6Zbzj7/t2BvWiYFQ6yF90Q=="},{"Hdr":{"Name":"debian.org.","Rrtype":48,"Class":1,"Ttl":28800,"Rdlength":200},"Flags":256,"Protocol":3,"Algorithm":8,"PublicKey":"AwEAAakBNMMPiUQg+KzNgTYM6+8stHJ0ESnwkDU9+wSxDADphK1KQL5e8KwU1rPJgMfK4rObAMvvLWQuJQBR3klZLbxXygOv3YVWMaUYL51XGMzOhlSOyfrdkfXGOT2adi29M3KVAiuJRc+7Ahd5rypDnZO4tLKci31/nECkvKcz8/lPLBNNOP0LtG8PHdDYpJAf/eKsqM2IBVR63aqUZ9+vVQIo3Ikm3nUvQP7Ie9lLaoBRPttaMrqpeR7vBIgnQE2FcQ=="}],"CDS":null,"CDNSKEY":null}
```

Or, in the case of a third-party trusted private key,

```json
{"delegation":["cloudflare.com."],"DNSKEY":[{"Hdr":{"Name":"cloud-surfer.net.","Rrtype":48,"Class":1,"Ttl":3600,"Rdlength":68},"Flags":257,"Protocol":3,"Algorithm":13,"PublicKey":"mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="},{"Hdr":{"Name":"cloud-surfer.net.","Rrtype":48,"Class":1,"Ttl":3600,"Rdlength":68},"Flags":256,"Protocol":3,"Algorithm":13,"PublicKey":"koPbw9wmYZ7ggcjnQ6ayHyhHaDNMYELKTqT+qRGrZpWSccr/lBcrm10Z1PuQHB3Azhii+sb0PYFkH1ruxLhe5g=="}],"CDS":null,"CDNSKEY":null}
```
