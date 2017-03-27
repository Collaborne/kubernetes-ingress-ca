#!/usr/bin/env node

'use strict';

const request = require('request');
const openssl = require('openssl-wrapper').exec;
const yargs = require('yargs');
const fs = require('fs');
const path = require('path');
const url = require('url');
const tmp = require('tmp');

const argv = yargs
	.default('secrets', 'tinyca')
	.alias('s', 'server').describe('server', 'The address and port of the Kubernetes API server')
	.alias('cacert', 'certificate-authority').describe('certificate-authority', 'Path to a cert. file for the certificate authority')
	.alias('cert', 'client-certificate').describe('client-certificate', 'Path to a client certificate file for TLS')
	.alias('key', 'client-key').describe('client-key', 'Path to a client key file for TLS')
	.boolean('insecure-skip-tls-verify').describe('insecure-skip-tls-verify', 'If true, the server\'s certificate will not be checked for validity. This will make your HTTPS connections insecure')
	.describe('token', 'Bearer token for authentication to the API server')
	.describe('self-signed-cn', 'CN for automatically provisioned self-signed root certificate')
	.default('self-signed-days', 1).describe('self-signed-days', 'Validity of self-signed root certificate')
	.default('namespace', 'default').describe('namespace', 'Namespace in which to create the secret')
	.default('secret', 'ingress-ca').describe('secret', 'Name of the secret containing the root CA certificates')
	.help()
	.argv;

/*
 * A tiny CA for use in Kubernetes
 *
 * This will watch Ingress resources, and if these are annotated with
 * 'kubernetes.collaborne.com/tls-ca': 'true' this CA will try to create
 * a suitable certificate.
 *
 * The only required configuration is the name of the Secrets resource that
 * contains the root CA certificate and key, in the `ca.pem` and `ca-key.pem`
 * entries.
 *
 * Kubernetes will be accessed using the 'default' ServiceAccount (see
 * https://kubernetes.io/docs/user-guide/service-accounts/).
 * TODO: Allow other methods of authentication for development.
 */

/** The basic configuration for accessing the API server using request */
let k8sConfig;
if (argv.server) {
	const fs = require('fs');

	k8sConfig = {
		url: argv.server,
		insecureSkipTlsVerify: argv.insecureSkipTlsVerify
	};
	if (argv.certificateAuthority) {
		k8sConfig.ca = fs.readFileSync(argv.certificateAuthority, 'utf8');
	}
	if (argv.token) {
		k8sConfig.auth = { bearer: argv.token };
	} else if (argv.username && argv.password) {
		k8sConfig.auth = { user: argv.username, pass: argv.password };
	} else if (argv.clientCertificate && argv.clientKey) {
		k8sConfig.cert = fs.readFileSync(argv.clientCertificate, 'utf8');
		k8sConfig.key = fs.readFileSync(argv.clientKey, 'utf8');
	}
} else if (process.env.KUBERNETES_SERVICE_HOST) {
	k8sConfig = {
		url: process.env.KUBERNETES_SERVICE_HOST,
		ca: fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt', 'utf8'),
		auth: { bearer: fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token', 'utf8') }
	}
} else {
	console.error('Unknown Kubernetes API server');
	process.exit(1);
}

const k8s = require('auto-kubernetes-client');

k8s(k8sConfig).then(function(k8sClient) {
	// Find the secret and read the certificate information from it.
	// The secret may be missing, or we might be missing data in it.
	k8sClient.ns(argv.namespace).secret(argv.secret).get().then(function(result) {
		if (result.kind === 'Status' && result.status === 'NotFound') {
			k8sClient.ns(argv.namespace).secrets.create({
				metadata: {
					name: argv.secret
				},
				stringData: {
					dummy: 'dummy'
				}
			}).then(function(secret) {
				console.log(`Created secret ${secret.metadata.name}`);
			});
		}
	});
	if (argv.selfSignedCaSubject) {
		// Create a self-signed root CA certificate
		// XXX: Should we verify whether that already exists in our secret?
		const config = `
			[req]
			distinguished_name=req_distinguished_name
			[req_distinguished_name]
			[ext]
			basicConstraints=CA:TRUE,pathlen:0`;
		// openssl req -config <(echo "$CONFIG") -new -newkey rsa:2048 -nodes -subj "/CN=Hello" -x509 -extensions ext -keyout key.pem -out crt.pem
		// Need to catch the files, so must provide a temp directory + filenames
		tmp.dir({ unsafeCleanup: true }, function(err, dir, cleanupCallback) {
			console.log(dir);
			fs.writeFileSync(path.resolve(dir, 'openssl.cnf'), config, { encoding: 'UTF-8' });
			openssl('req', new Buffer(config), {
				'batch': true,
				'new': true,
				'newkey': 'rsa:2048',
				'x509': true,
				'nodes': true,
				'subj': `/CN=${argv.selfSignedCaSubject}`,
				'keyout': path.resolve(dir, 'key.pem'),
				'out': path.resolve(dir, 'cert.pem'),
				'config': path.resolve(dir, 'openssl.cnf'),
				'extensions': 'ext',
			}, function(err, stdout) {
				if (err) {
					console.log(err.message);
				}
				console.log(stdout.toString('utf-8'));

				return cleanupCallback();
			});
		});
	}

	const ingresses = k8sClient.group('extensions', 'v1beta1').ns(argv.namespace).ingresses;
	ingresses.list().then(function(ingressList) {
		console.log(`list: * (${ingressList.metadata.resourceVersion})`);
		ingressList.items.forEach(function(item) {
			console.log(`list: ${item.metadata.name} (${item.metadata.resourceVersion})`);
		});

		ingresses.watch(ingressList.metadata.resourceVersion)
		.on('data', function(item) {
			console.log(`${item.type}: ${item.object.metadata.name}`);
		});
	});
});
