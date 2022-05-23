package io.bspk.httpsig;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Signature algorithms.
 * @author jricher
 *
 */
public class HttpSigAlgorithm {

	public static final HttpSigAlgorithm RSAPSS = new HttpSigAlgorithm("rsa-pss-sha512");
	public static final HttpSigAlgorithm RSA15 = new HttpSigAlgorithm("rsa-v1_5-sha256");
	public static final HttpSigAlgorithm HMAC = new HttpSigAlgorithm("hmac-sha256");
	public static final HttpSigAlgorithm ECDSA = new HttpSigAlgorithm("ecdsa-p256-sha256");
	public static final HttpSigAlgorithm ED25519 = new HttpSigAlgorithm("ed25519");
	public static final HttpSigAlgorithm JOSE = new HttpSigAlgorithm(null);

	@JsonValue
	private final String explicitAlg;

	/**
	 * @param object
	 */
	private HttpSigAlgorithm(String explicitAlg) {
		this.explicitAlg = explicitAlg;
	}

	/**
	 * @return the explicitAlg
	 */
	public String getExplicitAlg() {
		return explicitAlg;
	}

	/**
	 * @return
	 */
	@JsonCreator
	public static HttpSigAlgorithm of(String alg) {
		if (alg == null) {
			return null;
		} else if (alg.equalsIgnoreCase("jose")) {
			return JOSE;
		} else {
			return new HttpSigAlgorithm(alg);
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		HttpSigAlgorithm other = (HttpSigAlgorithm) obj;
		if (getExplicitAlg() == null) {
			if (other.getExplicitAlg() != null) {
				return false;
			}
		} else if (!getExplicitAlg().equals(other.getExplicitAlg())) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((getExplicitAlg() == null) ? 0 : getExplicitAlg().hashCode());
		return result;
	}

}
