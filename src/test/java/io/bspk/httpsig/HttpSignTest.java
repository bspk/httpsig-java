package io.bspk.httpsig;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Instant;
import java.util.Map;

import org.greenbytes.http.sfv.InnerList;
import org.greenbytes.http.sfv.Parameters;
import org.greenbytes.http.sfv.Parser;
import org.greenbytes.http.sfv.StringItem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HttpSignVerifyTest {

	private TestComponentProviders ctx;
	private TestKeys keys;


	@BeforeEach
	public void setup() {
		this.keys = TestKeys.getKeys();
		this.ctx  = TestComponentProviders.getProviders();
	}

	
	@Test
	public void testMinimal() {
		SignatureParameters params = new SignatureParameters()
			.setCreated(Instant.ofEpochSecond(1618884473))
			.setKeyid("test-key-rsa-pss")
			.setNonce("b3k2pp5k7z-50gnwp.yemd");
		
		String expectedParams = Crunchwrap.unwrap("();created=1618884473\\\n"
				+ "  ;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\"");
		
		assertEquals(expectedParams, params.toComponentValue().serialize());
		
		SignatureBaseBuilder signatureBaseBuilder = new SignatureBaseBuilder(params, ctx.TEST_REQUEST);

		byte[] base = signatureBaseBuilder.createSignatureBase();
		
		byte[] expected = Crunchwrap.unwrap("\"@signature-params\": ();created=1618884473;keyid=\"test-key-rsa-pss\"\\\n"
				+ "  ;nonce=\"b3k2pp5k7z-50gnwp.yemd\"").getBytes();
		
		assertArrayEquals(expected, base);
		
		HttpSign signer = new HttpSign(HttpSigAlgorithm.RSAPSS, TestKeys.getKeys().TEST_KEY_RSA_PSS);
		byte[] signed = signer.sign(base);
		
		HttpVerify verifier = new HttpVerify(HttpSigAlgorithm.RSAPSS, TestKeys.getKeys().TEST_KEY_RSA_PSS);
		boolean verified = verifier.verify(base, signed);
		
		assertTrue(verified);
	}

	@Test
	public void testSelective() {
		
		SignatureParameters params = new SignatureParameters()
			.setCreated(Instant.ofEpochSecond(1618884473))
			.setKeyid("test-key-rsa-pss")
			.setTag("header-example")
			.addComponentIdentifier("@authority")
			.addComponentIdentifier("content-digest")
			.addComponentIdentifier(StringItem.valueOf("@query-param")
					.withParams(Parameters.valueOf(Map.of("name", "Pet"))));
		
		String expectedParams = Crunchwrap.unwrap("(\"@authority\" \"content-digest\" \\\n"
				+ "  \"@query-param\";name=\"Pet\");created=1618884473\\\n"
				+ "  ;keyid=\"test-key-rsa-pss\";tag=\"header-example\"");
		
		assertEquals(expectedParams, params.toComponentValue().serialize());

		SignatureBaseBuilder signatureBaseBuilder = new SignatureBaseBuilder(params, ctx.TEST_REQUEST);

		byte[] base = signatureBaseBuilder.createSignatureBase();
		
		byte[] expected = Crunchwrap.unwrap("\"@authority\": example.com\n"
				+ "\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX\\\n"
				+ "  +TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n"
				+ "\"@query-param\";name=\"Pet\": dog\n"
				+ "\"@signature-params\": (\"@authority\" \"content-digest\" \\\n"
				+ "  \"@query-param\";name=\"Pet\")\\\n"
				+ "  ;created=1618884473;keyid=\"test-key-rsa-pss\"\\\n"
				+ "  ;tag=\"header-example\"").getBytes();
		
		assertArrayEquals(expected, base);
		
		HttpSign signer = new HttpSign(HttpSigAlgorithm.RSAPSS, TestKeys.getKeys().TEST_KEY_RSA_PSS);
		byte[] signed = signer.sign(base);
		
		HttpVerify verifier = new HttpVerify(HttpSigAlgorithm.RSAPSS, TestKeys.getKeys().TEST_KEY_RSA_PSS);
		boolean verified = verifier.verify(base, signed);
		
		assertTrue(verified);
	}

	@Test
	public void testFull() {
		
		SignatureParameters params = new SignatureParameters()
			.setCreated(Instant.ofEpochSecond(1618884473))
			.setKeyid("test-key-rsa-pss")
			.addComponentIdentifier("date")
			.addComponentIdentifier("@method")
			.addComponentIdentifier("@path")
			.addComponentIdentifier("@query")
			.addComponentIdentifier("@authority")
			.addComponentIdentifier("content-type")
			.addComponentIdentifier("content-digest")
			.addComponentIdentifier("content-length");
		
		String expectedParams = Crunchwrap.unwrap("(\"date\" \"@method\" \"@path\" \"@query\" \\\n"
				+ "  \"@authority\" \"content-type\" \"content-digest\" \"content-length\")\\\n"
				+ "  ;created=1618884473;keyid=\"test-key-rsa-pss\"");
		
		assertEquals(expectedParams, params.toComponentValue().serialize());

		SignatureBaseBuilder signatureBaseBuilder = new SignatureBaseBuilder(params, ctx.TEST_REQUEST);

		byte[] base = signatureBaseBuilder.createSignatureBase();
		
		byte[] expected = Crunchwrap.unwrap("\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n"
				+ "\"@method\": POST\n"
				+ "\"@path\": /foo\n"
				+ "\"@query\": ?param=Value&Pet=dog\n"
				+ "\"@authority\": example.com\n"
				+ "\"content-type\": application/json\n"
				+ "\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX\\\n"
				+ "  +TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n"
				+ "\"content-length\": 18\n"
				+ "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@query\" \\\n"
				+ "  \"@authority\" \"content-type\" \"content-digest\" \"content-length\")\\\n"
				+ "  ;created=1618884473;keyid=\"test-key-rsa-pss\"").getBytes();
		
		assertArrayEquals(expected, base);
		
		HttpSign signer = new HttpSign(HttpSigAlgorithm.RSAPSS, TestKeys.getKeys().TEST_KEY_RSA_PSS);
		byte[] signed = signer.sign(base);
		
		HttpVerify verifier = new HttpVerify(HttpSigAlgorithm.RSAPSS, TestKeys.getKeys().TEST_KEY_RSA_PSS);
		boolean verified = verifier.verify(base, signed);
		
		assertTrue(verified);
	}

	@Test
	public void testResponse() {
		
		SignatureParameters params = new SignatureParameters()
			.setCreated(Instant.ofEpochSecond(1618884473))
			.setKeyid("test-key-ecc-p256")
			.addComponentIdentifier("@status")
			.addComponentIdentifier("content-type")
			.addComponentIdentifier("content-digest")
			.addComponentIdentifier("content-length");
		
		String expectedParams = Crunchwrap.unwrap("(\"@status\" \"content-type\" \\\n"
				+ "  \"content-digest\" \"content-length\");created=1618884473\\\n"
				+ "  ;keyid=\"test-key-ecc-p256\"");
		
		assertEquals(expectedParams, params.toComponentValue().serialize());

		SignatureBaseBuilder signatureBaseBuilder = new SignatureBaseBuilder(params, ctx.TEST_RESPONSE);

		byte[] base = signatureBaseBuilder.createSignatureBase();
		
		byte[] expected = Crunchwrap.unwrap("\"@status\": 200\n"
				+ "\"content-type\": application/json\n"
				+ "\"content-digest\": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ4\\\n"
				+ "  1QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:\n"
				+ "\"content-length\": 23\n"
				+ "\"@signature-params\": (\"@status\" \"content-type\" \"content-digest\" \\\n"
				+ "  \"content-length\");created=1618884473;keyid=\"test-key-ecc-p256\"").getBytes();
		
		assertArrayEquals(expected, base);
		
		HttpSign signer = new HttpSign(HttpSigAlgorithm.ECDSA, TestKeys.getKeys().TEST_KEY_ECC_P256);
		byte[] signed = signer.sign(base);
		
		HttpVerify verifier = new HttpVerify(HttpSigAlgorithm.ECDSA, TestKeys.getKeys().TEST_KEY_ECC_P256);
		boolean verified = verifier.verify(base, signed);
		
		assertTrue(verified);
	}

	@Test
	public void testHmac() {
		
		SignatureParameters params = new SignatureParameters()
			.setCreated(Instant.ofEpochSecond(1618884473))
			.setKeyid("test-shared-secret")
			.addComponentIdentifier("date")
			.addComponentIdentifier("@authority")
			.addComponentIdentifier("content-type");
		
		String expectedParams = Crunchwrap.unwrap("(\"date\" \"@authority\" \"content-type\")\\\n"
				+ "  ;created=1618884473;keyid=\"test-shared-secret\"");
		
		assertEquals(expectedParams, params.toComponentValue().serialize());

		SignatureBaseBuilder signatureBaseBuilder = new SignatureBaseBuilder(params, ctx.TEST_REQUEST);

		byte[] base = signatureBaseBuilder.createSignatureBase();
		
		byte[] expected = Crunchwrap.unwrap("\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n"
				+ "\"@authority\": example.com\n"
				+ "\"content-type\": application/json\n"
				+ "\"@signature-params\": (\"date\" \"@authority\" \"content-type\")\\\n"
				+ "  ;created=1618884473;keyid=\"test-shared-secret\"").getBytes();
		
		assertArrayEquals(expected, base);
		
		HttpSign signer = new HttpSign(HttpSigAlgorithm.HMAC, TestKeys.getKeys().TEST_SHARED_SECRET);
		byte[] signed = signer.sign(base);
		
		HttpVerify verifier = new HttpVerify(HttpSigAlgorithm.HMAC, TestKeys.getKeys().TEST_SHARED_SECRET);
		boolean verified = verifier.verify(base, signed);
		
		assertTrue(verified);
	}

	@Test
	public void testEd25519() {
		
		SignatureParameters params = new SignatureParameters()
			.setCreated(Instant.ofEpochSecond(1618884473))
			.setKeyid("test-key-ed25519")
			.addComponentIdentifier("date")
			.addComponentIdentifier("@method")
			.addComponentIdentifier("@path")
			.addComponentIdentifier("@authority")
			.addComponentIdentifier("content-type")
			.addComponentIdentifier("content-length");
		
		String expectedParams = Crunchwrap.unwrap("(\"date\" \"@method\" \"@path\" \"@authority\" \\\n"
				+ "  \"content-type\" \"content-length\");created=1618884473\\\n"
				+ "  ;keyid=\"test-key-ed25519\"");
		
		assertEquals(expectedParams, params.toComponentValue().serialize());

		SignatureBaseBuilder signatureBaseBuilder = new SignatureBaseBuilder(params, ctx.TEST_REQUEST);

		byte[] base = signatureBaseBuilder.createSignatureBase();
		
		byte[] expected = Crunchwrap.unwrap("\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n"
				+ "\"@method\": POST\n"
				+ "\"@path\": /foo\n"
				+ "\"@authority\": example.com\n"
				+ "\"content-type\": application/json\n"
				+ "\"content-length\": 18\n"
				+ "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \\\n"
				+ "  \"content-type\" \"content-length\");created=1618884473\\\n"
				+ "  ;keyid=\"test-key-ed25519\"").getBytes();
		
		assertArrayEquals(expected, base);
		
		HttpSign signer = new HttpSign(HttpSigAlgorithm.HMAC, TestKeys.getKeys().TEST_SHARED_SECRET);
		byte[] signed = signer.sign(base);
		
		HttpVerify verifier = new HttpVerify(HttpSigAlgorithm.HMAC, TestKeys.getKeys().TEST_SHARED_SECRET);
		boolean verified = verifier.verify(base, signed);
		
		assertTrue(verified);
	}
}
