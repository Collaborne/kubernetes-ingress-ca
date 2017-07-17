#!/usr/bin/env node

'use strict';

const openssl = require('openssl-wrapper').exec;
const yargs = require('yargs');
const fs = require('fs');
const path = require('path');
const tmp = require('tmp');

const logger = require('log4js').getLogger();

const argv = yargs
	.alias('s', 'server').describe('server', 'The address and port of the Kubernetes API server')
	.alias('cacert', 'certificate-authority').describe('certificate-authority', 'Path to a cert. file for the certificate authority')
	.alias('cert', 'client-certificate').describe('client-certificate', 'Path to a client certificate file for TLS')
	.alias('key', 'client-key').describe('client-key', 'Path to a client key file for TLS')
	.boolean('insecure-skip-tls-verify').describe('insecure-skip-tls-verify', 'If true, the server\'s certificate will not be checked for validity. This will make your HTTPS connections insecure')
	.describe('token', 'Bearer token for authentication to the API server')
	.default('self-signed-cn', '/CN=kubernetes-ingress-ca').describe('self-signed-cn', 'CN for automatically provisioned self-signed root certificate')
	.default('namespace', 'default').describe('namespace', 'Namespace in which to create the secret')
	.default('secret', 'ingress-ca').describe('secret', 'Name of the secret containing the root CA certificates')
	.default('annotation', 'kubernetes.collaborne.com/tls-ingress-ca').describe('annotation', 'The annotation to check when searching for ingresses')
	.help()
	.argv;

/** The basic configuration for accessing the API server */
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
		url: `https://${process.env.KUBERNETES_SERVICE_HOST}:${process.env.KUBERNETES_SERVICE_PORT}`,
		ca: fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt', 'utf8'),
		auth: { bearer: fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token', 'utf8') }
	}
} else {
	logger.error('Unknown Kubernetes API server');
	process.exit(1);
}

const k8s = require('auto-kubernetes-client');

k8s(k8sConfig).then(function(k8sClient) {
	function createRootCertificatePair(subject) {
		// Create a self-signed root CA certificate
		const config = `
			[req]
			distinguished_name=req_distinguished_name
			[req_distinguished_name]
			[v3_ext]
			basicConstraints=CA:TRUE,pathlen:0`;
		return new Promise(function(resolve, reject) {
			tmp.dir({ unsafeCleanup: true }, function(err, dir, cleanupCallback) {
				fs.writeFileSync(path.resolve(dir, 'openssl.cnf'), config, { encoding: 'UTF-8' });
				const certPath = path.resolve(dir, 'cert.pem');
				const keyPath = path.resolve(dir, 'key.pem');
				openssl('req', {
					'batch': true,
					'new': true,
					'newkey': 'rsa:2048',
					'x509': true,
					'nodes': true,
					'subj': `/CN=${subject}`,
					'keyout': keyPath,
					'out': certPath,
					'config': path.resolve(dir, 'openssl.cnf'),
					'extensions': 'v3_ext',
				}, function(err, stdout) {
					logger.debug(stdout.toString('UTF-8'));
					if (err) {
						return reject(err);
					}

					const certificatePair = {
						cert: fs.readFileSync(certPath, 'UTF-8'),
						key: fs.readFileSync(keyPath, 'UTF-8')
					}
					
					if (typeof cleanupCallback === 'function') {
						cleanupCallback();
					}

					return resolve(certificatePair);
				});
			});
		});
	}

	function storeRootCertificatePair(ns, name, certificatePair) {
		// We now have the certificate and the key, and should be able to update the certificate with these.
		const update = {
			stringData: {
				'ca.crt': certificatePair.cert,
				'ca.key': certificatePair.key
			}
		};

		return k8sClient.ns(ns).secret(name).update(update).then(function(result) {
			if (result.kind === 'Status') {
				logger.warn(`Failed to update secret: ${result.reason} ${result.message}`);
			}
			return result;
		});
	}

	function extractRootCertificatePair(secret) {
		if (secret.data && secret.data['ca.crt'] && secret.data['ca.key']) {
			return {
				cert: Buffer.from(secret.data['ca.crt'], 'base64').toString('UTF-8'),
				key: Buffer.from(secret.data['ca.key'], 'base64').toString('UTF-8')
			};
		} else {
			return null;
		}
	}	

	function storeIngressCertificatePair(ns, name, certificatePair) {
		const update = {
			stringData: {
				'tls.crt': certificatePair.cert,
				'tls.key': certificatePair.key
			}
		};

		return k8sClient.ns(ns).secret(name).update(update).then(function(result) {
			if (result.kind === 'Status') {
				logger.warn(`Failed to update secret: ${result.reason} ${result.message}`);
			}
			return result;
		});
	}

	function extractIngressCertificatePair(secret) {
		if (secret.data && secret.data['tls.crt'] && secret.data['tls.key']) {
			return {
				cert: Buffer.from(secret.data['tls.crt'], 'base64').toString('UTF-8'),
				key: Buffer.from(secret.data['tls.key'], 'base64').toString('UTF-8')
			};
		} else {
			return null;
		}
	}

	function shouldProcessIngress(ingress) {
		return ingress.metadata.annotations && ingress.metadata.annotations[argv.annotation] === 'true';
	}

	function processIngress(ingress) {
		// Check whether this ingress has TLS information, and if so, whether the referenced secret exists.
		// If it does: all good, we just let things be. Eventually we will check the certificate and update it.
		// If the secret does not exist we try to create it.
		if (!ingress.spec.tls || ingress.spec.tls.length === 0) {
			return Promise.resolve();
		}

		const caPromises = ingress.spec.tls.map(function(tls) {
			return k8sClient.ns(ingress.metadata.namespace).secret(tls.secretName).get().catch(function(err) {
				if (err.kind === 'Status' && err.status === 'Failure' && err.reason === 'NotFound') {
					// Create the missing secret first
					logger.info(`Creating new secret ${ingress.metadata.namespace}/${tls.secretName}`);
					return k8sClient.ns(ingress.metadata.namespace).secrets.create({ metadata: { name: tls.secretName }});
				} else {
					// Some other error: throw this out further, hoping that someone will handle it better.
					logger.warn(`Cannot get secret ${ingress.metadata.namespace}/${tls.secretName}: ${err.message}`);
					throw err;
				}
			}).then(function(secret) {
				if (secret.kind !== 'Secret') {
					throw new Error(`${secret.status}: ${secret.message} (${secret.reason})`);
				}

				const certificatePair = extractIngressCertificatePair(secret);
				if (!certificatePair) {
					return createCertificatePair(tls.hosts).then(function(certificatePair) {
						logger.info(`Created certificate pair for ${secret.metadata.namespace}/${secret.metadata.name}`);
						return storeIngressCertificatePair(secret.metadata.namespace, secret.metadata.name, certificatePair).then(() => certificatePair);
					});
				} else {
					return certificatePair;
				}
			});
		});

		return Promise.all(caPromises);
	}

	function getRootCertificatePair(ns, name) {
		return k8sClient.ns(ns).secret(name).get().then(function(result) {
			if (result.kind === 'Status' && result.status === 'Failure') {
				if (result.reason === 'NotFound') {
					if (argv.selfSignedCn) {
						return k8sClient.ns(ns).secrets.create({ metadata: { name }}).then(function(secret) {
							return createRootCertificatePair(argv.selfSignedCn).then(function(rootCertificatePair) {
								return storeRootCertificatePair(secret.metadata.namespace, secret.metadata.name, rootCertificatePair).then(() => rootCertificatePair);
							});
						});
					} else {
						throw new Error(`No root certificate available in secret ${ns}/${name}, and no subject provided to create one`);
					}
				} else {
					throw new Error(`No root certificate available in secret ${ns}/${name}: ${result.reason} ${result.message}`);
				}
			} else if (result.kind === 'Secret') {
				const certificatePair = extractRootCertificatePair(result);
				if (certificatePair) {
					return certificatePair;
				} else {
					return createRootCertificatePair(argv.selfSignedCn).then(function(rootCertificatePair) {
						logger.info(`Created root certificate pair for ${result.metadata.namespace}/${result.metadata.name}`);
						return storeRootCertificatePair(result.metadata.namespace, result.metadata.name, rootCertificatePair).then(() => rootCertificatePair);
					});
				}
			} else {
				throw new Error(`Unexpected response for secret ${ns}/${name}: ${JSON.stringify(result)}`);
			}
		});
	}

	function createCertificatePair(hosts) {
		return getRootCertificatePair(argv.namespace, argv.secret).then(function(rootCertificatePair) {
			return new Promise(function(resolve, reject) {
				return tmp.dir({ unsafeCleanup: true }, function(err, dir, cleanupCallback) {
					// Create a new key first ...
					const keyPath = path.resolve(dir, 'key.pem');
					return openssl('genrsa', { 'out': keyPath , '2048': false }, function(err, stdout) {
						if (err) {
							return reject(err);
						}

						// ... then a CSR with all host information ...
						const confPath = path.resolve(dir, 'openssl.cnf');
						const csrPath = path.resolve(dir, 'cert.csr');
						// Use the first host for CN, but include all hosts in the subjectAlternativeName. Chrome 58, Firefox 48, and others
						// no longer look at the subject as per RFC2818 (https://www.chromestatus.com/feature/4981025180483584)
						const host = hosts[0];
						const altNames = hosts.map((host, index) => `DNS.${index + 1} = ${host}`).join('\n');

						let config = `
							[req]
							distinguished_name = req_distinguished_name
							[req_distinguished_name]
							[v3_ext]
							basicConstraints = CA:FALSE
							keyUsage = nonRepudiation, digitalSignature, keyEncipherment
							subjectAltName = @alt_names
							[alt_names]
							${altNames}`;

						fs.writeFileSync(confPath, config, { encoding: 'UTF-8' });
						return openssl('req', {
							'batch': true,
							'new': true,
							'key': keyPath,
							'out': csrPath,
							'subj': `/CN=${host}`,
							'config': confPath,
							'extensions': 'v3_ext' }, function(err, stdout) {
								if (err) {
									return reject(err);
								}

								// ... and finally create the certificate by signing with our CA
								const caCertPath = path.resolve(dir, 'ca-cert.pem');
								const caKeyPath = path.resolve(dir, 'ca-key.pem');
								const certPath = path.resolve(dir, 'cert.pem');
								fs.writeFileSync(caCertPath, rootCertificatePair.cert, 'UTF-8');
								fs.writeFileSync(caKeyPath, rootCertificatePair.key, 'UTF-8');

								return openssl('x509.req', {
									'in': csrPath,
									'out': certPath,
									'CA': caCertPath,
									'CAkey': caKeyPath,
									'CAcreateserial': true,
									'extensions': 'v3_ext',
									'extfile': confPath,
								}, function(err, stdout) {
									if (err) {
										return reject(err);
									}

									// Now create the certificate pair, and resolve the promise.
									const certificatePair = {
										cert: fs.readFileSync(certPath, 'UTF-8'),
										key: fs.readFileSync(keyPath, 'UTF-8')
									}
									
									if (typeof cleanupCallback === 'function') {
										cleanupCallback();
									}

									return resolve(certificatePair);
								});
							});
					});
				});
			});
		});
	}

	// Main "loop": list ingresses, and watch for changes. When watching finishes: re-sync.
	// Any ingress (ADDED/MODIFIED from watch, or whatever we see on list) is checked for valid certificates
	const ingresses = k8sClient.group('extensions', 'v1beta1').ns(argv.namespace).ingresses;
	const secrets = k8sClient.ns(argv.namespace).secrets;

	function mainLoop() {
		ingresses.list().then(function(ingressList) {
			logger.info(`Processing ${ingressList.items.length} ingresses at version ${ingressList.metadata.resourceVersion}`);
			ingressList.items.forEach(function(ingress) {
				if (shouldProcessIngress(ingress)) {
					logger.info(`Processing ${ingress.metadata.name}`);
					processIngress(ingress).then(function(certificatePairs) {
						logger.info(`Found/Created ${certificatePairs.length} certificate pairs for ${ingress.metadata.namespace}/${ingress.metadata.name}`);
					});
				}
			});

			logger.info('Watching ingresses...');
			ingresses.watch(ingressList.metadata.resourceVersion)
				.on('data', function(item) {
					if (shouldProcessIngress(item.object)) {
						switch (item.type) {
						case 'DELETED':
							// Delete the associated secret as well
							if (item.object.spec.tls) {
								item.object.spec.tls.forEach(function(tls) {
									if (tls.secretName) {
										secrets.name(tls.secretName).delete().then(function(result) {
											logger.info(`Deleted secret ${tls.secretName}: ${JSON.stringify(result)}`);
										});
									}							
								});
							}
							break;
						case 'ADDED':
						case 'MODIFIED':
							processIngress(item.object);
							break;
						default:
							logger.warn(`Unkown watch event type ${item.type}, ignoring`);
						}
					}
				})
				.on('end', function() {
					// Restart the whole thing.
					logger.info('Watch ended, re-syncing everything');
					return mainLoop();
				});
		});
	}

	// Start!
	mainLoop();
}).catch(function(err) {
	logger.error(`Uncaught error, aborting: ${err.message}`);
	process.exit(1);
});
