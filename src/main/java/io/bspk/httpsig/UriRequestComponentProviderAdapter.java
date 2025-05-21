package io.bspk.httpsig;

import java.net.URI;
import java.nio.charset.Charset;
import java.util.List;

import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.net.PercentCodec;
import org.apache.hc.core5.net.WWWFormCodec;

/**
 * @author jricher
 *
 */
public abstract class UriRequestComponentProviderAdapter extends RequestComponentProviderAdapter {


    private final URI uri;


    public UriRequestComponentProviderAdapter(URI uri)
    {
        this.uri = uri;
    }


    @Override
    public String getAuthority()
    {
        return uri.getAuthority();
    }


    @Override
    public String getScheme()
    {
        return uri.getScheme();
    }


    @Override
    public String getTargetUri()
    {
        return uri.toString();
    }


    @Override
    public String getRequestTarget()
    {
		String reqt = "";
		if (uri.getRawPath() != null) {
			reqt += uri.getRawPath();
		}
		if (uri.getRawQuery() != null) {
			reqt += "?" + uri.getRawQuery();
		}
		return reqt;
    }


    @Override
    public String getPath()
    {
        return uri.getPath();
    }


    @Override
    public String getQuery()
    {
        return "?" + uri.getQuery();
    }


    @Override
    public String getQueryParams(String name)
    {
        List<NameValuePair> params = WWWFormCodec.parse(getQuery(), Charset.defaultCharset());
        return params.stream()
                .filter(p -> p.getName().equals(name))
                .map(NameValuePair::getValue)
                .map(v -> PercentCodec.encode(v, Charset.defaultCharset()))
                .reduce((a, b) -> {
                    throw new IllegalArgumentException("Found two named parameters, unsupported opperation");
                })
                .orElse(null);
    }


}
