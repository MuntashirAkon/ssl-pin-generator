SSL Pin Generator
=================

Is a simple Java base util to generate SSL pins based on a certificate's Subject Public Key Info as described on [Adam Langley's Weblog](https://www.imperialviolet.org/2011/05/04/pinning.html) (a.k.a Public Key pinning). Pins are base-64 SHA-256 [default] hashes, consistent with the format Chromium uses for [static certificates](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/http/transport_security_state_static.pins). See [Chromium's pinsets](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/http/transport_security_state_static.json) for hostnames that are pinned in that browser.
 
I created this mainly to be compatible with [okhttp](https://square.github.io/okhttp/) 2.1+, but later added the option to specific which hashing algorithm can be used to make this compatible with Android's `<network-security-config>`.


## Usage

*Warning you should ensure you run this on a trusted network*

Requires JDK 11 or later.

```sh
java src/com/scottyab/ssl/util/SSLPinGenerator.java host[:port] [algorithm debug]
```

`algorithm` can be any algorithm supported by `MessageDigest`.

Alternatively, you can use the `gen_ssl_pins.sh` command:

```sh
./gen_ssl_pins.sh host[:port]|cert
```

With this command, you can also provide a certificate file instead of a host name. `openssl` must be installed in this case.

### Default

```sh
java src/com/scottyab/ssl/util/SSLPinGenerator.java example.com
```

Output:

```
**Run this on a trusted network**
Generating SSL pins for: example.com
sha256/iMMpIJdSf5VlClHaxZReyhaLxLsmZMMNAiA2pMR8/M4=
sha256/qBRjZmOmkSNJL0p70zek7odSIzqs/muR4Jk9xYyCP+E=
sha256/uUwZgwDOxcBXrQcntwu+kYFpkiVkOaezL0WYEZ3anJc=
```

Then if you are using okhttp add them to the `com.squareup.okhttp.CertificatePinner` like this (from the [okhttp java docs](https://github.com/square/okhttp/blob/92bf318a70a9e2194e626ff2c2f4266b0bbb09e5/okhttp/src/main/java/com/squareup/okhttp/CertificatePinner.java#L160)):

```java
CertificatePinner certificatePinner = new CertificatePinner.Builder()
        .add("example.com", "sha256/iMMpIJdSf5VlClHaxZReyhaLxLsmZMMNAiA2pMR8/M4=")
        .add("example.com", "sha256/qBRjZmOmkSNJL0p70zek7odSIzqs/muR4Jk9xYyCP+E=")
        .add("example.com", "sha256/uUwZgwDOxcBXrQcntwu+kYFpkiVkOaezL0WYEZ3anJc=")
        .build();
```

### Custom Hash

In this exmaple, we use SHA-256 to be compatible with Android's `<network-security-config>`.

```sh
./gen_ssl_pins.sh example.com
```

or,

```sh
java src/com/scottyab/ssl/util/SSLPinGenerator.java example.com sha-256 debug
```

Output:

```
**Run this on a trusted network**
Generating SSL pins for: example.com
0. Subject :  CN=*.example.com,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
Expiry date :  Thu Jan 15 15:59:59 PST 2026
sha256/iMMpIJdSf5VlClHaxZReyhaLxLsmZMMNAiA2pMR8/M4=
1. Subject :  CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
Expiry date :  Sun Apr 13 16:59:59 PDT 2031
sha256/qBRjZmOmkSNJL0p70zek7odSIzqs/muR4Jk9xYyCP+E=
2. Subject :  CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US
Expiry date :  Fri Jan 15 04:00:00 PST 2038
sha256/uUwZgwDOxcBXrQcntwu+kYFpkiVkOaezL0WYEZ3anJc=
```

This also shows the debug option to print out subject name to help identifiy which pin belongs to which cert in the chain.

## License 
The MIT License

Copyright (c) 2023 Muntashir Al-Islam
Copyright (c) 2014 Scott Alexander-Bown http://scottyab.com
