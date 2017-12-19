# kubernetes-ingress-ca [![Build Status](https://travis-ci.org/Collaborne/kubernetes-ingress-ca.svg?branch=master)](https://travis-ci.org/Collaborne/kubernetes-ingress-ca) [![Greenkeeper badge](https://badges.greenkeeper.io/Collaborne/kubernetes-ingress-ca.svg)](https://greenkeeper.io/)

A tiny CA for use in Kubernetes

This will watch Ingress resources, and if these are annotated with 'kubernetes.collaborne.com/tls-ingress-ca': 'true' this CA will try to create a suitable certificate.

The only required configuration is the name of the Secrets resource that contains the root CA certificate and key, in the `ca.crt` and `ca.key` entries.

Kubernetes will be accessed using the 'default' ServiceAccount (see https://kubernetes.io/docs/user-guide/service-accounts/).

## Usage

Deploy the CA into kubernetes:

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: ingress-ca
spec:
  replicas: 1
  template:
    metadata:
      labels:
        infrastructure: ingress-ca
    spec:
      containers:
      - name: ingress-ca
        image: collaborne/kubernetes-ingress-ca:v0.4.1
        args:
        - --namespace=$(POD_NAMESPACE)
        env:
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
```

Optionally you can pre-create the root certificate and key, otherwise the CA will generate a new one at startup:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ingress-ca
stringData:
  ca.crt: |-
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  ca.key: |-
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
```

## License

    MIT License

    Copyright (c) 2017 Collaborne

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
