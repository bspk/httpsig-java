package io.bspk.httpsig;

/**
 * @author jricher
 *
 */
public abstract class RequestComponentProviderAdapter implements ComponentProvider {

	@Override
	public String getStatus() {
		throw new IllegalArgumentException("Derived component not supported");
	}
}
