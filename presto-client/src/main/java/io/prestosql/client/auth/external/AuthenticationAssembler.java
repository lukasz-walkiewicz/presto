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
package io.prestosql.client.auth.external;

import com.google.common.base.Splitter;
import com.google.common.collect.Maps;
import io.prestosql.client.ClientException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.collect.ImmutableMap.toImmutableMap;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

class AuthenticationAssembler
{
    static final String REDIRECT_URI_FIELD = "x_redirect_server";
    static final String TOKEN_URI_FIELD = "x_token_server";

    private AuthenticationAssembler() {}

    public static ExternalAuthentication toAuthentication(String header)
    {
        requireNonNull(header, "header is null");
        checkArgument(header.startsWith("Bearer"), "Bearer header required, \"%s\" does not start with Bearer prefix", header);

        int space = header.indexOf(' ');
        String challenge = header.substring(space + 1);
        Map<String, String> fields = Splitter.on(",").trimResults()
                .splitToStream(challenge)
                .map(field -> Splitter.on("=").limit(2)
                        .splitToList(field))
                .filter(keyValue -> keyValue.size() == 2)
                .map(keyValue -> {
                    String value = keyValue.get(1);
                    checkArgument(value.startsWith("\"") && value.endsWith("\""), "Fields are required to be in quotation marks");

                    return Maps.immutableEntry(keyValue.get(0), value.substring(1, value.length() - 1));
                })
                .collect(toImmutableMap(Map.Entry::getKey, Map.Entry::getValue));

        if (fields.containsKey(REDIRECT_URI_FIELD) && fields.containsKey(TOKEN_URI_FIELD)) {
            return new ExternalAuthentication(parseField(fields, REDIRECT_URI_FIELD), parseField(fields, TOKEN_URI_FIELD));
        }
        if (fields.containsKey(TOKEN_URI_FIELD)) {
            return new ExternalAuthentication(parseField(fields, TOKEN_URI_FIELD));
        }
        throw new IllegalStateException(format("header \"%s\" does not contain %s or %s fields", header, REDIRECT_URI_FIELD, TOKEN_URI_FIELD));
    }

    private static URI parseField(Map<String, String> fields, String fieldKey)
    {
        try {
            String field = fields.get(fieldKey);
            return new URI(field);
        }
        catch (URISyntaxException e) {
            throw new ClientException(format("Parsing field \"%s\" to URI has failed", fieldKey), e);
        }
    }
}
