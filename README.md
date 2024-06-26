# authserver

# make new ents
```
go run -mod=mod entgo.io/ent/cmd/ent init <struct name>
```
https://github.com/ory/hydra/blob/master/persistence/sql/persister_jwk.go#L55
https://github.com/ory/hydra/blob/master/persistence/sql/persister_jwk.go#L45
https://github.com/ory/hydra/blob/master/persistence/sql/persister_jwk.go#L50


# some new work ideas
Certificates for SSH?
https://goteleport.com/blog/how-to-configure-ssh-certificate-based-authentication/
seperate user and host certs
Lets set up host certs first
CommonName is <service>-hostname and has the hostname in the list of subject alternative names
EKU SSL Client KU Digital signature

Get jaeger setup and traces sent to it
https://www.jaegertracing.io/docs/1.47/getting-started/

user management with certificates for wifi
freeradius - can we extend it to use our user accounts? How do we connect to network based policies?


# Planning
User management from the ui
    - list of users
    - registration of user
    - access control

Networking control
- setup authenticated network access
    - https://turunen.ee/setting-up-radius-on-a-raspberry-pi/
    - freeradius
- setup system tracking with certs
- setup network policies for controlling access to each system
    - istio as the control plane and envoy as the proxy istio passes configuration info to the proxies
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_setting-up-an-802-1x-network-authentication-service-for-lan-clients-using-hostapd-with-freeradius-backend_configuring-and-managing-networking
- https://networkradius.com/articles/2021/10/25/EAP-production-certificates.html


- setup nas to have the certificate, for the user to download, custom proxy code envoy + basic webserver. Send from the auth server on the HSM pi.

# zymbit
https://docs.zymbit.com/getting-started/zymkey4/quickstart/
Probably want seperate instances of certificate/secrets managers

# syft
`syft scan .`