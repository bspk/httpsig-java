package io.bspk.httpsig;

import org.greenbytes.http.sfv.StringItem;

/**
 * @author jricher
 *
 */
public abstract class ResponseComponentProviderAdapter implements ComponentProvider {

	private ComponentProvider requestComponentProvider;

	public void setRequestComponentProvider(ComponentProvider requestComponentProvider) {
		this.requestComponentProvider = requestComponentProvider;
	}


	public ComponentProvider getRequestComponentProvider() {
		return requestComponentProvider;
	}

	@Override
	public String getMethod() {
		throw new IllegalArgumentException("Derived component not supported");
	}

	@Override
	public String getAuthority() {
		throw new IllegalArgumentException("Derived component not supported");
	}

	@Override
	public String getScheme() {
		throw new IllegalArgumentException("Derived component not supported");
	}

	@Override
	public String getTargetUri() {
		throw new IllegalArgumentException("Derived component not supported");
	}

	@Override
	public String getRequestTarget() {
		throw new IllegalArgumentException("Derived component not supported");
	}

	@Override
	public String getPath() {
		throw new IllegalArgumentException("Derived component not supported");
	}

	@Override
	public String getQuery() {
		throw new IllegalArgumentException("Derived component not supported");
	}

	@Override
	public String getQueryParams(String name) {
		throw new IllegalArgumentException("Derived component not supported");
	}

	@Override
	public String getComponentValue(StringItem componentIdentifier) {
		if (componentIdentifier.getParams().containsKey("req")) {
			if (getRequestComponentProvider() != null) {
				return getRequestComponentProvider().getComponentValue(componentIdentifier);
			} else {
				throw new IllegalArgumentException("Request component not supported");
			}
		}
		return ComponentProvider.super.getComponentValue(componentIdentifier);
	}

}
