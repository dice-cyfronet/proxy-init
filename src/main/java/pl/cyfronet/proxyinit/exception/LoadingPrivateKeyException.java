/*
 * The contents of this file are subject to the license and copyright
 * terms detailed in the LICENSE.txt file at the root of the source
 * tree.
 */
package pl.cyfronet.proxyinit.exception;

/**
 * @author <a href="mailto:mkasztelnik@gmail.com">Marek Kasztelnik</a>
 */
public class LoadingPrivateKeyException extends Exception {

	private static final long serialVersionUID = 1L;
	
	public LoadingPrivateKeyException(String message) {
		super(message);
	}
}
