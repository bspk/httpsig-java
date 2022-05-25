package io.bspk.httpsig;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.greenbytes.http.sfv.Dictionary;
import org.greenbytes.http.sfv.InnerList;
import org.greenbytes.http.sfv.Item;
import org.greenbytes.http.sfv.ListElement;
import org.greenbytes.http.sfv.NumberItem;
import org.greenbytes.http.sfv.Parameters;
import org.greenbytes.http.sfv.StringItem;

/**
 * Carrier class for signature parameters.
 *
 * @author jricher
 *
 */
public class SignatureParameters {

	private List<StringItem> componentIdentifiers = new ArrayList<>();

	// this preserves insertion order
	private Map<String, Object> parameters = new LinkedHashMap<>();

	/**
	 * @return the componentIdentifiers
	 */
	public List<StringItem> getComponentIdentifiers() {
		return componentIdentifiers;
	}

	/**
	 * @param componentIdentifiers the componentIdentifiers to set
	 */
	public SignatureParameters setComponentIdentifiers(List<StringItem> componentIdentifiers) {
		this.componentIdentifiers = componentIdentifiers;
		return this;
	}

	/**
	 * @return the parameters
	 */
	public Map<String, Object> getParameters() {
		return parameters;
	}

	/**
	 * @param parameters the parameters to set
	 */
	public SignatureParameters setParameters(Map<String, Object> parameters) {
		this.parameters = parameters;
		return this;
	}

	/**
	 * @return the alg
	 */
	public HttpSigAlgorithm getAlg() {
		return (HttpSigAlgorithm) getParameters().get("alg");
	}

	/**
	 * @param alg the alg to set
	 */
	public SignatureParameters setAlg(HttpSigAlgorithm alg) {
		getParameters().put("alg", alg);
		return this;
	}

	/**
	 * @return the created
	 */
	public Instant getCreated() {
		return (Instant) getParameters().get("created");
	}

	/**
	 * @param created the created to set
	 */
	public SignatureParameters setCreated(Instant created) {
		getParameters().put("created", created);
		return this;
	}

	/**
	 * @return the expires
	 */
	public Instant getExpires() {
		return (Instant) getParameters().get("expires");
	}

	/**
	 * @param expires the expires to set
	 */
	public SignatureParameters setExpires(Instant expires) {
		getParameters().put("expires", expires);
		return this;
	}

	/**
	 * @return the keyid
	 */
	public String getKeyid() {
		return (String) getParameters().get("keyid");
	}

	/**
	 * @param keyid the keyid to set
	 */
	public SignatureParameters setKeyid(String keyid) {
		getParameters().put("keyid", keyid);
		return this;
	}

	/**
	 * @return the nonce
	 */
	public String getNonce() {
		return (String) getParameters().get("nonce");
	}

	/**
	 * @param nonce the nonce to set
	 */
	public SignatureParameters setNonce(String nonce) {
		getParameters().put("nonce", nonce);
		return this;
	}

	public StringItem toComponentIdentifier() {
		return StringItem.valueOf("@signature-params");
	}

	public InnerList toComponentValue() {

		// we do this cast to get around Java's generic type restrictions
		List<Item<? extends Object>> identifiers = componentIdentifiers.stream()
			.map(e -> (Item<? extends Object>) e)
			.collect(Collectors.toList());

		InnerList list = InnerList.valueOf(identifiers);

		Map<String, Object> params = new LinkedHashMap<>();

		// preserve order
		for (String paramName : getParameters().keySet()) {
			if (paramName.equals("alg")) {
				HttpSigAlgorithm alg = getAlg();
				if (alg.getExplicitAlg() != null) {
					params.put("alg", alg.getExplicitAlg());
				}
			} else if (paramName.equals("created")) {
				params.put("created", getCreated().getEpochSecond());
			} else if (paramName.equals("expires")) {
				params.put("expires", getExpires().getEpochSecond());
			} else if (paramName.equals("keyid")) {
				params.put("keyid", getKeyid());
			} else if (paramName.equals("nonce")) {
				params.put("nonce", getNonce());
			} else {
				params.put(paramName, getParameters().get(paramName));
			}
		}

		list = list.withParams(Parameters.valueOf(params));

		return list;
	}

	/**
	 * Add a component without parameters.
	 */
	public SignatureParameters addComponentIdentifier(String identifier) {
		if (!identifier.startsWith("@")) {
			componentIdentifiers.add(StringItem.valueOf(identifier.toLowerCase()));
		} else {
			componentIdentifiers.add(StringItem.valueOf(identifier));
		}
		return this;
	}

	/**
	 * Add a component with optional parameters. Field components are assumed to be
	 * already set to lowercase.
	 */
	public SignatureParameters addComponentIdentifier(StringItem identifier) {
		componentIdentifiers.add(identifier);
		return this;
	}

	// this ignores parameters
	public boolean containsComponentIdentifier(String identifier) {
		return componentIdentifiers.stream()
			.map(StringItem::get)
			.anyMatch(identifier::equals);
	}

	// does not ignore parameters
	public boolean containsComponentIdentifier(StringItem identifier) {
		return componentIdentifiers.stream()
			.filter((i) -> {
				return
					i.get().equals(identifier.get())
					&& i.getParams().equals(identifier.getParams());
			})
			.findAny()
			.isPresent();
	}

	/**
	 * @param signatureInput
	 * @param sigId
	 */
	public static SignatureParameters fromDictionaryEntry(Dictionary signatureInput, String sigId) {
		if (signatureInput.get().containsKey(sigId)) {
			ListElement<? extends Object> item = signatureInput.get().get(sigId);
			if (item instanceof InnerList) {
				InnerList coveredComponents = (InnerList)item;

				SignatureParameters params = new SignatureParameters()
					.setComponentIdentifiers(
						coveredComponents.get().stream()
							.map(StringItem.class::cast)
							.collect(Collectors.toList()));

				for (String key : coveredComponents.getParams().keySet()) {
					if (key.equals("alg")) {
						params.setAlg(HttpSigAlgorithm.of(((StringItem)coveredComponents.getParams().get("alg")).get()));
					} else if (key.equals("created")) {
						params.setCreated(
							Instant.ofEpochSecond(((NumberItem<?>)coveredComponents.getParams().get("created")).getAsLong()));
					} else if (key.equals("expires")) {
						params.setCreated(
							Instant.ofEpochSecond(((NumberItem<?>)coveredComponents.getParams().get("expires")).getAsLong()));
					} else  if (key.equals("keyid")) {
						params.setKeyid(((StringItem)coveredComponents.getParams().get("keyid")).get());
					} else if (key.equals("nonce")) {
						params.setNonce(((StringItem)coveredComponents.getParams().get("nonce")).get());
					} else {
						params.getParameters().put(key, coveredComponents.getParams().get(key).serialize()); // store the serialized version
					}
				}

				return params;

			} else {
				throw new IllegalArgumentException("Invalid syntax, identifier '" + sigId + "' must be an inner list");
			}
		} else {
			throw new IllegalArgumentException("Could not find identifier '" + sigId + "' in dictionary " + signatureInput.serialize());
		}

	}
}
