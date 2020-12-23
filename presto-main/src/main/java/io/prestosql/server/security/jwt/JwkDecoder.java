/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.prestosql.server.security.jwt;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableList;
import io.airlift.json.JsonCodec;
import io.airlift.log.Logger;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static com.google.common.base.Strings.isNullOrEmpty;
import static com.google.common.collect.ImmutableMap.toImmutableMap;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;

public final class JwkDecoder
{
    private static final Logger log = Logger.get(JwkDecoder.class);
    private static final JsonCodec<Keys> KEYS_CODEC = JsonCodec.jsonCodec(Keys.class);

    private JwkDecoder() {}

    public static Map<String, PublicKey> decodeKeys(String jwkJson)
    {
        Keys keys = KEYS_CODEC.fromJson(jwkJson);
        return keys.getKeys().stream()
                .map(JwkDecoder::tryDecodeJwkKey)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(toImmutableMap(JwkPublicKey::getKeyId, Function.identity()));
    }

    public static Optional<? extends JwkPublicKey> tryDecodeJwkKey(Key key)
    {
        // key id is required to index the key
        if (key.getKid().isEmpty() || key.getKid().get().isEmpty()) {
            return Optional.empty();
        }
        String keyId = key.getKid().get();
        switch (key.getKty()) {
            case "RSA":
                return tryDecodeRsaKey(keyId, key);
            case "EC":
                return tryDecodeEcKey(keyId, key);
            default:
                // ignore non unknown keys
                return Optional.empty();
        }
    }

    public static Optional<JwkRsaPublicKey> tryDecodeRsaKey(String keyId, Key key)
    {
        // alg field is optional so not verified
        // use field is optional so not verified

        Object encodedModulus = key.getOther().get("n");
        if (!(encodedModulus instanceof String)) {
            log.error("JWK RSA key %s contains invalid value '%s' for modulus field 'n'", keyId, encodedModulus);
            return Optional.empty();
        }
        if (isNullOrEmpty((String) encodedModulus)) {
            log.error("JWK RSA key %s does not contain the required modulus field 'n'", keyId);
            return Optional.empty();
        }

        Object encodedExponent = key.getOther().get("e");
        if (!(encodedExponent instanceof String)) {
            log.error("JWK RSA key %s contains invalid value '%s' for exponent field 'e'", keyId, encodedExponent);
            return Optional.empty();
        }
        if (isNullOrEmpty((String) encodedExponent)) {
            log.error("JWK RSA key %s does not contain the required exponent field 'e'", keyId);
            return Optional.empty();
        }

        Optional<BigInteger> modulus = decodeBigint(keyId, "modulus", (String) encodedModulus);
        if (modulus.isEmpty()) {
            return Optional.empty();
        }
        Optional<BigInteger> exponent = decodeBigint(keyId, "exponent", (String) encodedExponent);
        if (exponent.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new JwkRsaPublicKey(keyId, exponent.get(), modulus.get()));
    }

    public static Optional<JwkEcPublicKey> tryDecodeEcKey(String keyId, Key key)
    {
        // alg field is optional so not verified
        // use field is optional so not verified

        Object curveName = key.getOther().get("crv");
        if (!(curveName instanceof String)) {
            log.error("JWK EC key %s contains invalid value '%s' for curve field 'crv'", keyId, curveName);
            return Optional.empty();
        }
        if (isNullOrEmpty((String) curveName)) {
            log.error("JWK EC key %s does not contain the required curve field 'crv'", keyId);
            return Optional.empty();
        }

        Object encodedX = key.getOther().get("x");
        if (!(encodedX instanceof String)) {
            log.error("JWK EC key %s contains invalid value '%s' for x coordinate field 'x'", keyId, encodedX);
            return Optional.empty();
        }
        if (isNullOrEmpty((String) encodedX)) {
            log.error("JWK EC key %s does not contain the required x coordinate field 'x'", keyId);
            return Optional.empty();
        }

        Object encodedY = key.getOther().get("y");
        if (!(encodedY instanceof String)) {
            log.error("JWK EC key %s contains invalid value '%s' for y coordinate field 'y'", keyId, encodedX);
            return Optional.empty();
        }
        if (isNullOrEmpty((String) encodedY)) {
            log.error("JWK EC key %s does not contain the required y coordinate field 'y'", keyId);
            return Optional.empty();
        }

        Optional<ECParameterSpec> curve = EcCurve.tryGet((String) curveName);
        if (curve.isEmpty()) {
            log.error("JWK EC %s curve '%s' is not supported", keyId, curveName);
            return Optional.empty();
        }
        Optional<BigInteger> x = decodeBigint(keyId, "x", (String) encodedX);
        if (x.isEmpty()) {
            return Optional.empty();
        }
        Optional<BigInteger> y = decodeBigint(keyId, "y", (String) encodedY);
        if (y.isEmpty()) {
            return Optional.empty();
        }

        ECPoint w = new ECPoint(x.get(), y.get());
        return Optional.of(new JwkEcPublicKey(keyId, curve.get(), w));
    }

    private static Optional<BigInteger> decodeBigint(String keyId, String fieldName, String encodedNumber)
    {
        try {
            return Optional.of(new BigInteger(1, getUrlDecoder().decode(encodedNumber)));
        }
        catch (IllegalArgumentException e) {
            log.error(e, "JWK %s %s is not a valid number", keyId, fieldName);
            return Optional.empty();
        }
    }

    public interface JwkPublicKey
            extends PublicKey
    {
        String getKeyId();
    }

    public static class JwkRsaPublicKey
            implements JwkPublicKey, RSAPublicKey
    {
        private final String keyId;
        private final BigInteger modulus;
        private final BigInteger exponent;

        public JwkRsaPublicKey(String keyId, BigInteger exponent, BigInteger modulus)
        {
            this.keyId = requireNonNull(keyId, "keyId is null");
            this.exponent = requireNonNull(exponent, "exponent is null");
            this.modulus = requireNonNull(modulus, "modulus is null");
        }

        @Override
        public String getKeyId()
        {
            return keyId;
        }

        @Override
        public BigInteger getModulus()
        {
            return modulus;
        }

        @Override
        public BigInteger getPublicExponent()
        {
            return exponent;
        }

        @Override
        public String getAlgorithm()
        {
            return "RSA";
        }

        @Override
        public String getFormat()
        {
            return "JWK";
        }

        @Override
        public byte[] getEncoded()
        {
            throw new UnsupportedOperationException();
        }
    }

    public static class JwkEcPublicKey
            implements JwkPublicKey, ECPublicKey
    {
        private final String keyId;
        private final ECParameterSpec parameterSpec;
        private final ECPoint w;

        public JwkEcPublicKey(String keyId, ECParameterSpec parameterSpec, ECPoint w)
        {
            this.keyId = requireNonNull(keyId, "keyId is null");
            this.parameterSpec = requireNonNull(parameterSpec, "parameterSpec is null");
            this.w = requireNonNull(w, "w is null");
        }

        @Override
        public String getKeyId()
        {
            return keyId;
        }

        @Override
        public ECParameterSpec getParams()
        {
            return parameterSpec;
        }

        @Override
        public ECPoint getW()
        {
            return w;
        }

        @Override
        public String getAlgorithm()
        {
            return "EC";
        }

        @Override
        public String getFormat()
        {
            return "JWK";
        }

        @Override
        public byte[] getEncoded()
        {
            throw new UnsupportedOperationException();
        }
    }

    public static class Keys
    {
        private final List<Key> keys;

        @JsonCreator
        public Keys(@JsonProperty("keys") List<Key> keys)
        {
            this.keys = ImmutableList.copyOf(requireNonNull(keys, "keys is null"));
        }

        public List<Key> getKeys()
        {
            return keys;
        }
    }

    public static class Key
    {
        private final String kty;
        private final Optional<String> kid;
        private final Map<String, Object> other = new HashMap<>();

        @JsonCreator
        public Key(
                @JsonProperty("kty") String kty,
                @JsonProperty("kid") Optional<String> kid)
        {
            this.kty = requireNonNull(kty, "kty is null");
            this.kid = requireNonNull(kid, "kid is null");
        }

        public String getKty()
        {
            return kty;
        }

        public Optional<String> getKid()
        {
            return kid;
        }

        @JsonAnyGetter
        public Map<String, Object> getOther()
        {
            return other;
        }

        @JsonAnySetter
        public void set(String name, Object value)
        {
            other.put(name, value);
        }
    }
}
