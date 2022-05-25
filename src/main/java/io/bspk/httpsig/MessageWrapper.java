package io.bspk.httpsig;

import org.apache.commons.lang3.RandomStringUtils;

/**
 * @author jricher
 *
 */
public interface MessageWrapper {

	default void addSignature(SignatureParameters signatureInput, byte[] signature) {
		String sigId = RandomStringUtils.randomAlphabetic(5).toLowerCase();

		addSignature(sigId, signatureInput, signature);
	}

	void addSignature(String signatureId, SignatureParameters signatureInput, byte[] signature);

}
