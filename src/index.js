#!/usr/bin/env node

'use strict';

const request = require('request');
const openssl = require('openssl-wrapper').exec;
const yargs = require('yargs');
const fs = require('fs');
const path = require('path');
const url = require('url');

const argv = yargs
	.default('secrets', 'tinyca')
	.alias('s', 'server').describe('server', 'The address and port of the Kubernetes API server')
	.alias('cacert', 'certificate-authority').describe('certificate-authority', 'Path to a cert. file for the certificate authority')
	.alias('cert', 'client-certificate').describe('client-certificate', 'Path to a client certificate file for TLS')
	.alias('key', 'client-key').describe('client-key', 'Path to a client key file for TLS')
	.boolean('insecure-skip-tls-verify').describe('insecure-skip-tls-verify', 'If true, the server\'s certificate will not be checked for validity. This will make your HTTPS connections insecure')
	.describe('token', 'Bearer token for authentication to the API server')    
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

k8s(k8sConfig, function(error, k8sClient) {
	const ingresses = k8sClient.group('extensions', 'v1beta1').ns('master').ingresses;
	function listAndWatch(err, response, ingressList) {
		if (err) {
			console.log(`list error: ${err.message}`);
			return;
		}
		
		ingressList.items.forEach(function(item) {			
			console.log(`list: ${item.metadata.name} (${item.metadata.resourceVersion}`);
		});
		ingresses.watch(function(err, item) {
			if (err) {
				console.error(`watch error: ${err.message}`);
				return;
			}

			if (item === null) {
				// Watch timed out, restart it.
				// XXX: How do we know the new version? Best to start from scratch, and list the current resources
				//      again.
				console.log('Reconciling after watch finished')
				return ingresses.list(listAndWatch);
			}
			console.log(`${item.type}: ${item.object.metadata.name}`);
		}, ingressList.metadata.resourceVersion);
	}
	
	ingresses.list(listAndWatch);
});