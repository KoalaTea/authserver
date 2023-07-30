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
