package io.bspk.httpsig;

import java.net.URI;
import java.util.Map;
import java.util.TreeMap;

public class TestComponentProviders {

	private static TestComponentProviders instance;

	/**
	 * A component provider for the following message:
	 * 
	 * POST /foo?param=Value&Pet=dog HTTP/1.1
	 * Host: example.com
	 * Date: Tue, 20 Apr 2021 02:07:55 GMT
	 * Content-Type: application/json
	 * Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+T\
  	 *   aPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
	 * Content-Length: 18
	 * 
	 * {"hello": "world"}
	 * 
	 */
	public final ComponentProvider TEST_REQUEST;
	
	/**
	 * A component provider for the following message:
	 * 
	 * HTTP/1.1 200 OK
	 * Date: Tue, 20 Apr 2021 02:07:56 GMT
	 * Content-Type: application/json
	 * Content-Digest: sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41Q\
	 *   JgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:
	 * Content-Length: 23
	 * 
	 * {"message": "good dog"}
	 * 
	 */
	public final ComponentProvider TEST_RESPONSE;
	
	
	
	private TestComponentProviders() {
		
		URI reqUri = URI.create("https://example.com/foo?param=Value&Pet=dog");
		final Map<String, String> reqFields = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);		
		reqFields.putAll(Map.of(
			"Host", "example.com",
			"Date", "Tue, 20 Apr 2021 02:07:55 GMT",
			"Content-Type", "application/json",
			"Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
			"Content-Length", "18"));
		
		TEST_REQUEST = new UriRequestComponentProviderAdapter(reqUri) {
			
			@Override
			public String getMethod() {
				return "POST";
			}
			
			@Override
			public String getField(String name) {
				return reqFields.get(name);
			}
		};

		final Map<String, String> resFields = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
		resFields.putAll(Map.of(
				 "Date", "Tue, 20 Apr 2021 02:07:56 GMT",
				 "Content-Type", "application/json",
				 "Content-Digest", "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:",
				 "Content-Length", "23"));

		
		TEST_RESPONSE = new ResponseComponentProviderAdapter() {

			@Override
			public String getStatus() {
				return "200";
			}

			@Override
			public String getField(String name) {
				return resFields.get(name);
			}
			
		};
		
	}
	
	public static TestComponentProviders getProviders() {
		if (instance == null) {
			instance = new TestComponentProviders();
		}
		
		return instance;
	}
	
	
}
