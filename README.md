# scep-webhook-validator

A basic dynamic SCEP webhook validation server example 

## Prerequisites

* A [step-ca](https://github.com/smallstep/certificates/) instance with Remote Administration and the insecure address `"insecureAddress"` configured.
* A SCEP provisioner configured with a `SCEPCHALLENGE` webhook.
* An ACME provisioner.
* A SCEP client, requesting a certificate using a challenge password.

## Usage

```console
./scep-webhook-validator -help
Usage of scep-webhook-validator
  -directory string
    	The ACME directory URL to use (default "https://127.0.0.1:8443/acme/acme/directory")
  -root string
    	Path to the root certificate to trust
  -secret string
    	The webhook shared secret
```

Example usage:

```console
./scep-webhook-validator -directory https://127.0.0.1:8443/acme/acme/directory -root /path/to/root.crt -secret MTIzNAo=
```

The example uses the [step-ca](https://github.com/smallstep/certificates/) ACME directory at [https://127.0.0.1:8443/acme/acme/directory](https://127.0.0.1:8443/acme/acme/directory) to request a certificate, because all webhook servers must use HTTPS.
The `root` can be provided to point the root of [step-ca](https://github.com/smallstep/certificates/) instance, so that when the built-in ACME client connects to the server, the HTTPS connection will be trusted.
An ACME provisioner named `acme` is configured with the following settings:

```json
    {
        "type": "ACME",
        "name": "acme",
    },
```

The `secret` is optional, but if provided, should be equal to the `Secret` returned when adding the `SCEPCHALLENGE` webhook.

The SCEP provisioner should look similar to the one below:

```json
    {
        "type": "SCEP",
        "name": "scepca",
        "challenge": "*** REDACTED ***",
        "minimumPublicKeyLength": 2048,
        "encryptionAlgorithmIdentifier": 2,
        "options": {
            "webhooks": [
                {
                    "id": "6d230d9c-1a51-4ff9-950f-9923dd68a177",
                    "name": "scepchallenge",
                    "url": "https://127.0.0.1:8081/scepvalidate",
                    "kind": "SCEPCHALLENGE",
                    "certType": "ALL"
                }
            ]
        },
    }
```
