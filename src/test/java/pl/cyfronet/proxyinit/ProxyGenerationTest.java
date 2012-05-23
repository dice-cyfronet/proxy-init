/*
 * The contents of this file are subject to the license and copyright
 * terms detailed in the LICENSE.txt file at the root of the source
 * tree.
 */
package pl.cyfronet.proxyinit;

import static com.googlecode.catchexception.CatchException.caughtException;
import static com.googlecode.catchexception.apis.CatchExceptionBdd.then;
import static com.googlecode.catchexception.apis.CatchExceptionBdd.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.io.File;

import org.globus.gsi.GSIConstants;
import org.globus.gsi.GlobusCredential;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import pl.cyfronet.proxyinit.exception.LoadingCertificateException;
import pl.cyfronet.proxyinit.exception.LoadingPrivateKeyException;
import pl.cyfronet.proxyinit.exception.WrongPasswordException;

/**
 * @author <a href="mailto:mkasztelnik@gmail.com">Marek Kasztelnik</a>
 */
public class ProxyGenerationTest {

	private static final String CERT_PATH = ".globus/proxytestcert.pem";
	private static final String KEY_PATH = ".globus/proxytestkey.pem";
	private static final String PASSWORD = "experimentworkbench";

	@Test
	public void shouldGenerateProxy() throws Exception {
		// given
		File certFile = getFile(CERT_PATH);
		File keyFile = getFile(KEY_PATH);

		// when
		GlobusCredential proxy = new ProxyBuilder().loadCertificate(certFile)
				.loadPrivateKey(keyFile, PASSWORD).generateProxy();

		// then
		assertTrue(proxy.getIdentity().contains(
				"O=Dice Team/OU=ACK CYFRONET AGH/CN=Proxy Test"));
		assertEquals(proxy.getProxyType(), GSIConstants.GSI_2_PROXY);
	}

	@Test
	public void shouldNotDecryptPrivateKey() throws Exception {
		// given
		File keyFile = getFile(KEY_PATH);

		when(new ProxyBuilder())
			.loadPrivateKey(keyFile, "wrong" + PASSWORD);

		then(caughtException())
			.isInstanceOf(WrongPasswordException.class);
	}

	@DataProvider
	protected Object[][] getWrongCertFiles() {
		return new Object[][] {
				{getFile(KEY_PATH), "File does not cointain any valid certificate"},
				{null, "Certificate file does not exist"}
		};
	}
	
	@Test(dataProvider = "getWrongCertFiles")
	public void shouldThwrowExceptionWhileLoadingWrongCertificate(File wrongCertFile, String errorMessage) throws Exception {
		when(new ProxyBuilder())
			.loadCertificate(wrongCertFile);

		then(caughtException())
			.isInstanceOf(LoadingCertificateException.class)
			.hasMessage(errorMessage);
	}

	@DataProvider
	protected Object[][] getWrongPrivateKeyFiles() {
		return new Object[][] {
				{getFile(CERT_PATH)},
				{null}
		};
	}
	
	@Test(dataProvider = "getWrongPrivateKeyFiles")
	public void shouldLoadWrongPrivateKey(File wrongPrivKeyFile) throws Exception {
		when(new ProxyBuilder())
			.loadPrivateKey(wrongPrivKeyFile, PASSWORD);
		
		then(caughtException())
			.isInstanceOf(LoadingPrivateKeyException.class);
	}
	
	private File getFile(String keyPath) {
		return new File(getClass().getClassLoader().getResource(keyPath)
				.getPath());
	}
}
