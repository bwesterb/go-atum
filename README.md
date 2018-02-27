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
 2.  Atum has a simple REST/json based API.

Go example
----------
To create a timestamp on some nonce, run

```go
tsBytes, err := atum.JsonStamp("https://some.atum/server", someNonce)
```

This returns a Json encoded version of the timestamp.
To check whether this timestamp is valid, run

```go
valid, _ := atum.Verify(tsBytes)
```

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

See `atum -h` for more options.

Protocol
--------

TODO: describe the Atum protocol.

Server
------

Want to run your own Atum server?  Check out [atumd](
    https://github.com/bwesterb/atumd).
