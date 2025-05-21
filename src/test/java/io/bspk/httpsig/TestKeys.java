/**
 * 
 */
package io.bspk.httpsig;

import java.text.ParseException;
import java.util.stream.Collectors;

import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;

/**
 *  Test keys from RFC9421.
 */
public final class TestKeys {

	// keys
	public final JWK TEST_KEY_RSA;
	public final JWK TEST_KEY_ED25519;
	public final JWK TEST_KEY_ECC_P256;
	public final JWK TEST_KEY_RSA_PSS;
	public final JWK TEST_SHARED_SECRET;
	
	// singleton
	private static TestKeys instance;
	
	public TestKeys() throws ParseException {
		TEST_KEY_RSA = JWK.parse(Crunchwrap.unwrap("{\n"
			+ "  \"kty\": \"RSA\",\n"
			+ "  \"kid\": \"test-key-rsa\",\n"
			+ "  \"p\": \"sqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOMcCNq8Sy\\\n"
			+ "  YbTqgnWlB9ZfcAm_cFpA8tYci9m5vYK8HNxQr-8FS3Qo8N9RJ8d0U5CswDzMYfRgh\\\n"
			+ "  AfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1mw\",\n"
			+ "  \"q\": \"vSlgXQbvHzWmuUBFRHAejRh_naQTDV3GnH4lcRHuFBFZCSLn82xQS2_7xFO\\\n"
			+ "  qfabqq17kNcvKfzdvWpGxxJ2cILAq0pZS6DmrZlvBU4IkK2ZHCac_XfWVZFh-PrsH\\\n"
			+ "  _EnVkDpfcYR_iw1F40C1q5w8R6WBHaew3SAp\",\n"
			+ "  \"d\": \"b8lm5JZ2hUduLnq-OAKCSODeWQ7Uqs7eet2bqeuAD0_2po-PG4qhZoo7VwF\\\n"
			+ "  CUTWlJan9wqdxiAPlbEQKkCdFRcbakbjN2TMJjMCHWL5zfgvqhmgeyKsrqg1wSce9\\\n"
			+ "  7J1_Mkvn3fh6CbqnwNb6bVFDvTJS3i5FzRhKiv6rUsYm8ZAdF4XRaYkFkeuHPl7rc\\\n"
			+ "  -ruUTSAjC4GovxIxoDJFe0r4kbFmkiZOr40e8RZYK7T1IKrSvzfxx5AjnlK_OZOTC\\\n"
			+ "  q0L7wBPbMW-IxmQpFCjpI-yuoi3FlZG3LaLNrBMXQF_lLZUDHs77q3fAGxDWwum2h\\\n"
			+ "  KBfdBuUQtjlqwjQlgXPsskQ\",\n"
			+ "  \"e\": \"AQAB\",\n"
			+ "  \"qi\": \"PkbARLOwU_LcZrQy9mmfcPoQlAuCyeu1Q9nH7PYSnbHTFzmiud4Hl8bIXU\\\n"
			+ "  9a0_58blDoOl3PctF-b4rAEJYUpCODu5PFyN6uEFYRg-YQwpjBMkXk8Eb39128ctA\\\n"
			+ "  RB40Lx8caDhRdTyaEedIG3cQDXSpAl9EOzXkzfx4bZxjAHU9mkMdJwOcMDQ\",\n"
			+ "  \"dp\": \"aiodZsrWpi8HFfZfeRs8OS_0L5x6WBl3Y9btoZgsIeruc9uZ8NXTIdxaM6\\\n"
			+ "  FdnyNEyOYA1VH94tDYR-xEt1br1ud_dkPslLV_Aac7d7EaYc7cdkb7oC9t6sphVg0\\\n"
			+ "  dqE0UTDlOwBxBYMtGmQbJsFzGpmjzVgKqWqJ3B947li2U7t63HXEvKprY2w\",\n"
			+ "  \"dq\": \"b0DzpSMb5p42dcQgOTU8Mr4S6JOEhRr_YjErMkpaXUEqvZ3jEB9HRmcRi5\\\n"
			+ "  Gtt4NBiBMiY6V9br8a5gjEpiAQoIUcWokBMAYjEeurU8M6JLBd3YaZVVjISaFmdty\\\n"
			+ "  nwLFoQxCh6_EC1rSywwrfDpSwO29S9i8Xbaap\",\n"
			+ "  \"n\": \"hAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrwWEBnez6\\\n"
			+ "  d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFqMGmXCQvE\\\n"
			+ "  G7YemcxDTRPxAleIAgYYRjTSd_QBwVW9OwNFhekro3RtlinV0a75jfZgkne_YiktS\\\n"
			+ "  vLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0PuKxI4T-HIa\\\n"
			+ "  Fpv8-rdV6eUgOrB2xeI1dSFFn_nnv5OoZJEIB-VmuKn3DCUcCZSFlQPSXSfBDiUGh\\\n"
			+ "  wOw76WuSSsf1D4b_vLoJ10w\"\n"
			+ "}"));
		
		TEST_KEY_RSA_PSS = JWK.parse(Crunchwrap.unwrap("{\n"
				+ "  \"kty\": \"RSA\",\n"
				+ "  \"kid\": \"test-key-rsa-pss\",\n"
				+ "  \"p\": \"5V-6ISI5yEaCFXm-fk1EM2xwAWekePVCAyvr9QbTlFOCZwt9WwjUjhtKRus\\\n"
				+ "  i5Uq-IYZ_tq2WRE4As4b_FHEMtp2AER43IcvmXPqKFBoUktVDS7dThIHrsnRi1U7d\\\n"
				+ "  HqVdwiMEMe5jxKNgnsKLpnq-4NyhoS6OeWu1SFozG9J9xQk\",\n"
				+ "  \"q\": \"w-wIde17W5Y0Cphp3ZZ0uM8OUq1AkrV2IKauqYHaDxAT32EM4ci2MMER2nI\\\n"
				+ "  UEo4g_42lW0zYouFFqONwv0-HyOsgPpdSqKRC5WLgn0VXabjaNcy6KhNPXeJ0Agtq\\\n"
				+ "  diDwPeJ2_L_eKwNWQ43RfdQBUquAwSd7SEmmQ8sViqB628M\",\n"
				+ "  \"d\": \"lAfIqfpCYomVShfAKnwf2lD9I0wKjkHsCtZCif4kAlwQqqW6N-tIL3bdOR-\\\n"
				+ "  VWf0Q1ZBIDtpO91UrG7pansyrPERbNrRJlPiYEyPTHkCT1nD-l2isuiyGLNBNnFoK\\\n"
				+ "  fBgA4KAbPJZQatFIV9Cn34JSHnpN5-2ehreGBYHtkwHFtlmzeF3yu5bqRcqOhx8lk\\\n"
				+ "  YmBzDAEUFyyXjknU5-WjAT9DzuG0MpOTkcU1EnjnIjyVBZLUB5Lxm8puyq8hH8B_E\\\n"
				+ "  5LNC-1oc8j-tDy98UvRTTiYvZvs87cGCFxg0LijNhg7CE3g9piNqB6DzMgA9MHSOw\\\n"
				+ "  cElVtfKdYfo4H3OHZXsSmEQ\",\n"
				+ "  \"e\": \"AQAB\",\n"
				+ "  \"qi\": \"jRAqfYi_tKCjhP9eM0N2XaRlNeoYCTx06GlSLD8d0zc4ZZuEePY10LMGWI\\\n"
				+ "  6Y_JC0CvvvQYhNa9sAj4hFjIVLsWeTplVVUezGO1ofLW4kYWVpnMpHgAY1pRM4kyz\\\n"
				+ "  o1p3MKYY8DE1BA4KqhSOfhdGs6Ov3Dfj0migZeE7Fu7yc7Fc\",\n"
				+ "  \"dp\": \"otDolkxtJ7Sk8gmRJqZCGx6GAvlGznWJfibXPv6xgUAl-G83dD84YgcNGn\\\n"
				+ "  oeMxRzEekfDtT5LVMRPF4_AoucsqPqHDyOdfb-dlGBYfOBVxj6w-xF5HE0lV_4J-H\\\n"
				+ "  rI63Od9fTSn4lY5d1JjyCVJIcnBEAyiD6EUZbUBh23vDzRcE\",\n"
				+ "  \"dq\": \"iZE1S6CpqmBoQDxOsXGQmaeBdhoCqkDSJhEDuS_dLhBq88FQa0UkcE1QvO\\\n"
				+ "  K3J2Q21VnfDqGBx7SH1hOFOj-cpz45kNluB832ztxDvnHQ9AIA7h_HY_3VD6YPMNR\\\n"
				+ "  VN4bfSYS3abdLR0Z7jsmInGJ9X0_fA0E2tkZIgXeas5EFU0M\",\n"
				+ "  \"n\": \"r4tmm3r20Wd_PbqvP1s2-QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvM\\\n"
				+ "  s8ct-Lh1GH45x28Rw3Ry53mm-oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95An\\\n"
				+ "  dTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL-Wokqltd11\\\n"
				+ "  nqqzi-bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSy\\\n"
				+ "  ZYoA485mqcO0GVAdVw9lq4aOT9v6d-nb4bnNkQVklLQ3fVAvJm-xdDOp9LCNCN48V\\\n"
				+ "  2pnDOkFV6-U9nV5oyc6XI2w\"\n"
				+ "}"));
		
		TEST_KEY_ECC_P256 = JWK.parse(Crunchwrap.unwrap("{\n"
				+ "  \"kty\": \"EC\",\n"
				+ "  \"crv\": \"P-256\",\n"
				+ "  \"kid\": \"test-key-ecc-p256\",\n"
				+ "  \"d\": \"UpuF81l-kOxbjf7T4mNSv0r5tN67Gim7rnf6EFpcYDs\",\n"
				+ "  \"x\": \"qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA\",\n"
				+ "  \"y\": \"Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0\"\n"
				+ "}"));
		
		TEST_KEY_ED25519 = JWK.parse(Crunchwrap.unwrap("{\n"
				+ "  \"kty\": \"OKP\",\n"
				+ "  \"crv\": \"Ed25519\",\n"
				+ "  \"kid\": \"test-key-ed25519\",\n"
				+ "  \"d\": \"n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU\",\n"
				+ "  \"x\": \"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs\"\n"
				+ "}"));
		
		TEST_SHARED_SECRET = new OctetSequenceKey.Builder(Base64URL.from(Crunchwrap.unwrap("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBt\\\n"
				+ "  bmHhIDi6pcl8jsasjlTMtDQ=="))).build();
	}
	
	public static TestKeys getKeys() {
		if (instance == null) {
			try {
				instance = new TestKeys();
			} catch (ParseException e) {
				e.printStackTrace();
			}
		}
		
		return instance;
	}

}
