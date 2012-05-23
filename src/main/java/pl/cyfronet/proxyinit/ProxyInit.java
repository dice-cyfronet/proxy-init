/*
 * The contents of this file are subject to the license and copyright
 * terms detailed in the LICENSE.txt file at the root of the source
 * tree.
 */
package pl.cyfronet.proxyinit;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.globus.gsi.CertUtil;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.OpenSSLKey;
import org.globus.gsi.X509ExtensionSet;
import org.globus.gsi.bc.BouncyCastleCertProcessingFactory;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;

import pl.cyfronet.proxyinit.exception.LoadingCertificateException;
import pl.cyfronet.proxyinit.exception.LoadingPrivateKeyException;
import pl.cyfronet.proxyinit.exception.ProxyGenerationException;
import pl.cyfronet.proxyinit.exception.WrongPasswordException;


/**
 * @author <a href="mailto:mkasztelnik@gmail.com">Marek Kasztelnik</a>
 * 
 */
public class ProxyInit {
	private static final int DEFAULT_BITS = 512;

	private static final int DEFAULT_LIFETIME = 3600 * 24;

	private static final int DEFAULT_PROXY_TYPE = GSIConstants.GSI_2_PROXY;

	private static BouncyCastleCertProcessingFactory factory = BouncyCastleCertProcessingFactory
			.getDefault();

	private List<X509Certificate> certList;

	private PrivateKey userKey;

	private X509ExtensionSet extSet = null;

	private GlobusCredential proxy;

	ProxyInit() {

	}

	public GlobusCredential getProxy() {
		return proxy;
	}

	void generateProxy() throws ProxyGenerationException {
		int bits = DEFAULT_BITS;
		int lifetime = DEFAULT_LIFETIME;
		int proxyType = DEFAULT_PROXY_TYPE;

		try {
			proxy = factory.createCredential(
					certList.toArray(new X509Certificate[0]), userKey, bits,
					lifetime, proxyType, extSet);
		} catch (GeneralSecurityException e) {
			throw new ProxyGenerationException(e.getMessage());
		}
	}

	void loadCertificate(File certFile) throws LoadingCertificateException {
		if (doesNotExist(certFile)) {
			throw new LoadingCertificateException(
					"Certificate file does not exist");
		}
		certList = new ArrayList<X509Certificate>();
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(certFile));
			X509Certificate cert = null;
			while ((cert = CertUtil.readCertificate(reader)) != null) {
				certList.add(cert);
			}
			if (certList.size() == 0) {
				throw new LoadingCertificateException(
						"File does not cointain any valid certificate");
			}
		} catch (IOException e) {
			throw new LoadingCertificateException(e.getMessage());
		} catch (GeneralSecurityException e) {
			throw new LoadingCertificateException(e.getMessage());
		} finally {
			close(reader);
		}

	}

	private boolean doesNotExist(File file) {
		return file == null || !file.exists();
	}

	void loadPrivateKey(File keyFile, String pwd)
			throws LoadingPrivateKeyException, WrongPasswordException {
		if (doesNotExist(keyFile)) {
			throw new LoadingPrivateKeyException(
					"Private key file does not exist");
		}
		InputStream is = null;
		try {
			is = new FileInputStream(keyFile);
			OpenSSLKey key = new BouncyCastleOpenSSLKey(is);
			decrypt(key, pwd);
			userKey = key.getPrivateKey();
		} catch (IOException e) {
			throw new LoadingPrivateKeyException(e.getMessage());
		} catch (GeneralSecurityException e) {
			throw new LoadingPrivateKeyException(e.getMessage());
		} finally {
			close(is);
		}
	}

	private void decrypt(OpenSSLKey key, String pwd)
			throws WrongPasswordException {
		if (key.isEncrypted()) {
			try {
				key.decrypt(pwd);
			} catch (InvalidKeyException e) {
				throw new WrongPasswordException();
			} catch (GeneralSecurityException e) {
				throw new WrongPasswordException();
			}
		}
	}

	private void close(Closeable closeable) {
		if (closeable != null) {
			try {
				closeable.close();
			} catch (IOException e) {
			}
		}
	}
}
