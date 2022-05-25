package io.bspk.httpsig.spring;

import java.util.Map;

import org.greenbytes.http.sfv.ByteSequenceItem;
import org.greenbytes.http.sfv.Dictionary;
import org.springframework.http.HttpRequest;

import io.bspk.httpsig.MessageWrapper;
import io.bspk.httpsig.SignatureParameters;

/**
 * @author jricher
 *
 */
public class RestTemplateMessageWrapper implements MessageWrapper {

	private HttpRequest request;

	public RestTemplateMessageWrapper(HttpRequest request) {
		this.request = request;
	}

	@Override
	public void addSignature(String signatureId, SignatureParameters signatureInput, byte[] signature) {
		Dictionary sigHeader = Dictionary.valueOf(Map.of(
			signatureId, ByteSequenceItem.valueOf(signature)));

		Dictionary sigInputHeader = Dictionary.valueOf(Map.of(
			signatureId, signatureInput.toComponentValue()));

		request.getHeaders().add("Signature", sigHeader.serialize());
		request.getHeaders().add("Signature-Input", sigInputHeader.serialize());
	}


}
