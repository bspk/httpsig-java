[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.bspk/httpsig/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.bspk/httpsig)

This is a Java implementation of [HTTP Message Signatures](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-08.html). An online sandbox for testing and viewing HTTP Message Signatures is available at <https://httpsig.org>.

Requires Java 14+.

## Maven Coordinates

``` xml
<dependency>
  <groupId>io.bspk</groupId>
  <artifactId>httpsig</artifactId>
  <version>0.0.3</version>
</dependency>
```

## Usage

To use this library, you need to supply an implementation of `ComponentProvider` to provide the message components for the signature base. Several providers are included for Java Spring, for both server-side and client side HTTP. Custom implementations of this interface can also be provided.

### Signing

To sign an HTTP message, first create the set of `SignatureParameters` and add the required covered component identifiers. Then create the signature base string, and finally pass this to the signing primitive.

In this example, `signingKey` is a `JWK` object from the Nimbus JOSE JWT library, and the Apache Commons Lang `RandomStringUtils` is used to provide randomized values in several places. The `request` variable is a `HttpRequest` object from a Spring Rest Template, here accessed using a `ClientHttpRequestInterceptor` implementation.

First, we create our parameters:

``` java
SignatureParameters sigParams = new SignatureParameters()
  .setCreated(Instant.now())
  .setKeyid(signingKey.getKeyID())
  .setNonce(RandomStringUtils.randomAlphanumeric(13))
  .addComponentIdentifier("@target-uri")
  .addComponentIdentifier("@method")
  .addComponentIdentifier("Authorization");
```

We then create our signature base, in this case using the `RestTemplateProvider` implementation for Spring Rest Templates.

``` java
SignatureContext ctx = new RestTemplateProvider(request);
SignatureBaseBuilder baseBuilder = new SignatureBaseBuilder(sigParams, ctx);
byte[] baseBytes = baseBuilder.createSignatureBase();
```

We can now pass this signature base into the cryptographic primative, with our signing key. Note that we have to explicitly provide an `HttpSigAlgorithm` here even though we didn't specify it in the signature parameters.

``` java
HttpSign httpSign = new HttpSign(httpSigAlgorithm, signingKey);
byte[] s = httpSign.sign(baseBytes);
```

Finally, we can take our signature parameters and signed content to create headers that we can add to our request message.

``` java
String sigId = RandomStringUtils.randomAlphabetic(5).toLowerCase();

Dictionary sigHeader = Dictionary.valueOf(Map.of(
  sigId, ByteSequenceItem.valueOf(s)));

Dictionary sigInputHeader = Dictionary.valueOf(Map.of(
  sigId, sigParams.toComponentValue()));

request.getHeaders().add("Signature", sigHeader.serialize());
request.getHeaders().add("Signature-Input", sigInputHeader.serialize());
```

### Verify

To sign an HTTP message, first extract the signature value and `SignatureParameters` from the headers of the request message. Next, ensure that the expected parts of the message are covered by the signature. Then create the signature base string, and finally pass this to the verification primitive.

In this example, we're running on a Spring servlet container and using the `HttpServletRequestProvider` implementation from the library. The string `sigId` is the identifier of the signature we are verifying. The variable `verificationKey` is a `JWK` object that contains the public verification key.

First, we extract the values from the headers. Both `signature` and `signatureInput` have already been parsed as `Dictionary` structured headers.

``` java
SignatureParameters sigParams = SignatureParameters.fromDictionaryEntry(signatureInput, sigId);
ByteSequenceItem sigValue = (ByteSequenceItem) signature.get().get(sigId);
```

Next, we make sure the covered components include the required items.

``` java
if (sigParams.containsComponentIdentifier("@method")
  && (sigParams.containsComponentIdentifier("@target-uri"))
  && (sigParams.containsComponentIdentifier("Authorization"))) {
```

Next, we create a provider context and create the signature base.

``` java
SignatureContext ctx = new HttpServletRequestProvider(request);

SignatureBaseBuilder baseBuilder = new SignatureBaseBuilder(sigParams, ctx);

byte[] baseBytes = baseBuilder.createSignatureBase();
```

Now, we extract the signature and pass it to the verification function along with our verification key. Note that we have to pass in an explicit `HttpSigAlgorithm` value to create the verifier, whether or not one is included in the signature parameters.

``` java
HttpVerify verify = new HttpVerify(httpSigAlgorithm, verifyKey);

ByteBuffer bb = sigValue.get();
byte[] sigBytes = new byte[bb.remaining()];
bb.get(sigBytes);

if (!verify.verify(baseBytes, sigBytes)) {
  throw new RuntimeException("Bad Signature, no biscuit");
}
```

The `verify()` function returns a boolean that indicates whether the signature verified or not given the input parameters. In this case we throw an error if it doesn't verify.
