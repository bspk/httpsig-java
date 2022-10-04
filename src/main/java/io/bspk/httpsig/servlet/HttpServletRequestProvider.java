package io.bspk.httpsig.servlet;

import java.net.URI;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;

import io.bspk.httpsig.ComponentProvider;
import io.bspk.httpsig.UriRequestComponentProviderAdapter;

/**
 * @author jricher
 *
 */
public class HttpServletRequestProvider extends UriRequestComponentProviderAdapter {

	private HttpServletRequest request;

	public HttpServletRequestProvider(HttpServletRequest request) {
		super(URI.create(request.getRequestURL().toString()
			+ (request.getQueryString() != null ? "?" + request.getQueryString() : "")));
		this.request = request;
	}

	@Override
	public String getMethod() {
		return request.getMethod();
	}

	@Override
	public String getStatus() {
		throw new UnsupportedOperationException("Requests cannot return a status code");
	}

	@Override
	@SuppressWarnings("unchecked") // we know the enumeration returns strings
	public String getField(String name) {
		return ComponentProvider.combineFieldValues(Collections.list(request.getHeaders(name)));
	}

}
