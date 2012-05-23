/*
 * The contents of this file are subject to the license and copyright
 * terms detailed in the LICENSE.txt file at the root of the source
 * tree.
 */
package pl.cyfronet.proxyinit;

import java.io.File;

import org.globus.gsi.GlobusCredential;

import pl.cyfronet.proxyinit.exception.LoadingCertificateException;
import pl.cyfronet.proxyinit.exception.LoadingPrivateKeyException;
import pl.cyfronet.proxyinit.exception.ProxyGenerationException;
import pl.cyfronet.proxyinit.exception.WrongPasswordException;

/**
 * @author <a href="mailto:mkasztelnik@gmail.com">Marek Kasztelnik</a>
 *
 */
public class ProxyBuilder {

	private ProxyInit proxyInit;
	
	public ProxyBuilder() {
		proxyInit = new ProxyInit();
	}
	
	public ProxyBuilder loadCertificate(File certFile)
			throws LoadingCertificateException {
		proxyInit.loadCertificate(certFile);
		return this;
	}
	
	public ProxyBuilder loadPrivateKey(File keyFile, String pwd)
			throws LoadingPrivateKeyException, WrongPasswordException {
		proxyInit.loadPrivateKey(keyFile, pwd);
		return this;
	}
	
	public GlobusCredential generateProxy() throws ProxyGenerationException {
		proxyInit.generateProxy();
		return proxyInit.getProxy();
	}
}
