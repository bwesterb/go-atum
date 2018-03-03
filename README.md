go-atum
=======

Go client (and CLI tool) to the [Atum trusted timestamping server](
    https://github.com/bwesterb/atumd).
So, why use Atum instead of [RFC 3161](https://tools.ietf.org/html/rfc3161)
    or [ANSI ASC X9.95](https://en.wikipedia.org/wiki/ANSI_ASC_X9.95_Standard)?

 1.  Atum timestamps use [XMSSMT hash-based signatures](
     https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/)
     by default, which are safe, even against an adversary with
     a large quantum computer.
 2.  Atum has a simple REST/json based API.  See below.

Go example
----------
To create a timestamp on some nonce, run

```go
tsBytes, err := atum.JsonStamp("https://some.atum/server", someNonce)
```

This returns a Json encoded version of the timestamp.
To check whether this timestamp is valid, run

```go
valid, tsServer _ := atum.Verify(tsBytes, nonce)
```

As anyone can run their own Atum server, you should check whether you
should trust the Atum server that signed the timestamp (`tsServer` in the
example above).

By default, the Atum server issues XMSSMT signatures, which are somewhat large
in size. To request an Ed25519 signature, which is smaller, but not safe
against an attacker with a quantum computer, use

```go
alg := atum.Ed25519
ts, err := atum.SendRequest("https://some.atum/server",
                    atum.Request{
                        Nonce: someNonce,
                        PreferredSigAlg: &alg
                    })
```

The `ts` is an `*atum.Timestamp`, which can be serialized using
`ts.MarshalText()` or simply `json.Marshal(ts)`.

For further documentation, see [godoc](
    https://godoc.org/github.com/bwesterb/go-atum).


Commandline tool
----------------

To create a timestamp on a file `some-document` (with a default Atum server),
run:

```
atum stamp -f some-document
```

This will create an `some-document.atum-timestamp` file.

To check the timestamp, run

```
atum verify -f some-document
```

This will tell whether the timestamp is valid and by which server it was set.
Like before, anyone can set up an Atum server, so you should check whether
you trust the Atum server which set the timestamp.

To check for a specific server, run

```
atum verify -f some-document -S https://some.atum/server
```

This will fail if the document is not signed by that specific Atum server.

See `atum -h` for more options.

Server
------

Want to run your own Atum server?  Check out [atumd](
    https://github.com/bwesterb/atumd).

Protocol
--------

An Atum server is a webservice and is identified by the url it runs at.  An example of an Atum server is

    https://metrics.privacybydesign.foundation/atum
    
### Request a timestamp

To request a timestamp for the nonce `example nonce`, simply POST

```json
{"Nonce": "ZXhhbXBsZSB0b2tlbg=="}
```

to the Atum server url.  If everything is fine, the server will respond with

```
{
 "Error": null,
 "Stamp": (the json encoded Atum timestamp),
 "Info": null
}
```

If there is a problem, the `Error` field will be one `missing nonce`,
`nonce is too long`, `proof of work is missing`,
`proof of work is invalid` or `too much lag`. Also, if helpful, the
`Info` field will include the server information, see below.

### Atum timestamp for a nonce

An example of a (json encoded) Atum timestamp (for the nonce `example nonce`) is

```json
{
 "Time": 1520078016,
 "ServerUrl": "https://metrics.privacybydesign.foundation/atum",
 "Sig": {
  "Alg":"ed25519",
  "Data":"L6Pig67OOXI01YuY8798o3F8RA6ehVI2UFc+wa2X4uOu9f6SrfkATb6ZexUKj8HfrHYTn2fK9Xna9rGAFYyWDg==",
  "PublicKey":"e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8="
}
```

* `Time` contains the [unix time](https://en.wikipedia.org/wiki/Unix_time)
   when the stamp was set.  In this case march 3rd, 2018 at 11:53:36 UTC.
* `ServerUrl` contains the url of the server which set the timestamp.
* `Alg` is the signature algorithm used.  Either `ed25519` or `xmssmt`.
* `PublicKey` contains the base64 encoded public key of the private
   key which was used to create the signature.
* `Data` contains a base64 encoded [Ed25519](https://ed25519.cr.yp.to)
   or [XMSSMT](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/)
   signature of the unix time (uint64, encoded big endian) concatenated
   with the nonce.

Note that the timestamp does not include the nonce itself.
To check a timestamp, one verifies the signature, but also should verify
that the public key belongs to the Atum server.  More on this later.

### Server information

A GET request to the url of the Atum server, will return a Json object like

```json
{
 "MaxNonceSize": 128,
 "AcceptableLag": 60,
 "DefaultSigAlg": "xmssmt",
 "RequiredProofOfWork": {
   "xmssmt": "sha2bday-16-T3oAQ2oV2VIdO5LqOLyrCsOEOr+86AhOyRnR37Vja8I"
 }
}
```

* `MaxNonceSize` is the maximum size of a nonce in bytes which the Atum
  server will sign.
* `AcceptableLag` is the largest difference in seconds the Atum server
  will accept between the requested time for a timestamp and the actual time.
* `DefaultSigAlg` is the default signature algorithm used.  See below.
* `RequiredProofOfWork` is a map that lists for which signature algorithms
  what [go-pow proof of work](https://github.com/bwesterb/go-pow)
  the server requires (if any).

This is the same Json object that might appear in `Info` field
in the response to a timestamp POST request.

### Optional request fields

A timestamp request (which is POSTed to the server url) may contain the
following optional fields.

* `PreferredSigAlg` to specify which kind of signature is preferred.
* `Time` to request the time on the timestamp.  This can't differ too much
  from the actual local time (as dictated by `AcceptableLag`).

For instance, this requests an `ed25519` signature for the UNIX time 1520078016.

```json
{
 "Nonce": "ZXhhbXBsZSB0b2tlbg==",
 "Time": 1520078016,
 "PreferredSigAlg": "ed25519"
}
```

### Proof of work

The server can be configured to require a proof of work before it will create
a timestamp with a certain signature scheme.  By default, `ed25519` does not
require a proof of work, but `xmssmt` does.

The [go-pow proof of work](https://github.com/bwesterb/go-pow) request is
contained in the server information and changes, by default, daily.
To fulfil the proof of work, the message that is to be signed for the timestamp
(uint64 unix time concatenated with the nonce) must be used as bound data.
This also means that `Time` should be specified in the request.
The resulting proof is put in the `ProofOfWork` field of the POSTed request.

An example for the PoW-request `sha2bday-16-T3oAQ2oV2VIdO5LqOLyrCsOEOr+86AhOyRnR37Vja8I` is

```json
{
 "Nonce":"4ihcK00BmuSQloyRH1kTrJ1/dfmSN5VkNSlDwEl+S+Lyxa2sfzg+t3v7pW6XhYZ8OBsblWgR+byLujVlnVNhpA==",
 "ProofOfWork":"AAAAAAAAAWIAAAAAAAACmwAAAAAAAAZh",
 "Time":1520081097
}
```

### Atum timestamp of a file (or longer message)

To timestamp  a file (which is too long to be a nonce), a hash is used.
An example of an Atum timestamp on an [old versionof this README](
https://github.com/bwesterb/go-atum/blob/55050e92e28492a76c8b29aff4c94dae4621721b/README.md)
is

```json
{
 "Time": 1520081260,
 "ServerUrl": "https://metrics.privacybydesign.foundation/atum",
 "Sig": {
   "Alg": "ed25519",
   "Data": "G/HCNLL/ZGkonGcDX4eIMysPw5Pw49vCsQ3wuFbo4dBd81HG8EGfwBsYBfPFCwyudrOW0jTxbNhcGvQG52VHDA==",
   "PublicKey":"e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8="
 },
 "Hashing": {
  "Hash": "shake256",
  "Prefix": "3hGOzeS3h/Wm9FKa8RbXvrdHNqk/N1ZzFKDdnSpdoqg="
 }
}
```

The nonce is computed by hashing the base64-decoded `Prefix` and then the file.
Currently only `shake256` is supported, which is
[SHA3's SHAKE-256](https://en.wikipedia.org/wiki/SHA-3)
where a 64-byte nonce is extracted.

### Lookup a public key

To verify an Atum timestamp, a client must check whether the public key
is valid for the given Atum server.  To do this, she sends a GET request
with query parameters `alg` for the algorithm and `pk` for the hex encoded
public key to `<server url>/checkPublicKey`.  For example, a GET to

    https://metrics.privacybydesign.foundation/atum/checkPublicKey?alg=ed25519&pk=7bf9cc00917b9f0aef359469b89963369471f82b13edc69a5f29fd397ebcdd1f

returned

```json
{
 "Trusted": true,
 "Expires": "2018-04-02T14:59:06.164300986+02:00"
}
```

but

    https://metrics.privacybydesign.foundation/atum/checkPublicKey?alg=ed25519&pk=7b

would return

```json
{
 "Trusted": false,
 "Expires": "2018-04-02T14:59:06.164300986+02:00"
}
```

The `Expires` field contains the time after which the client should check back
with the server whether the public key is still trusted.

Other remarks
-------------

1. **Trusted server.**
   Anyone can run an Atum server, which might or might not be honest.
   It is not sufficient to check that an Atum timestamp is valid: you should
   ensture that you trust the Atum server by which it was set.
2. **`xmssmt` or `ed25519`**
   The `ed25519` signatures are significantly smaller (0.4kB versus 2kB
   for `XMSSMT-SHA2_40/2_512`) and faster to create and verify.
   `xmssmt` is still very fast, it takes approximately 5ms to create or
   verify a signature for `XMSSMT-SHA2_40/2_512`.
   The big difference is that `ed25519` is easily broken by someone in
   possesion of a moderately sized quantum computer, which we are likely
   to see within the next 50 years.  On the other hand, it seems very
   unlikely that `XMSSMT-SHA2_40/2_512` will be broken in the forseeable
   future.
