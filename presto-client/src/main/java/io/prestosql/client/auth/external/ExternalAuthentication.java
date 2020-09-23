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

import com.google.common.annotations.VisibleForTesting;
import io.airlift.units.Duration;
import io.prestosql.client.ClientException;
import net.jodah.failsafe.ExecutionContext;
import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.RetryPolicy;

import java.net.URI;
import java.util.Optional;

import static java.lang.Math.max;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

class ExternalAuthentication
{
    private final Optional<URI> redirectUri;
    private final URI tokenUri;

    public ExternalAuthentication(URI redirectUri, URI tokenUri)
    {
        this.redirectUri = Optional.of(requireNonNull(redirectUri, "redirectUri is null"));
        this.tokenUri = requireNonNull(tokenUri, "tokenUri is null");
    }

    public ExternalAuthentication(URI tokenUri)
    {
        this.redirectUri = Optional.empty();
        this.tokenUri = requireNonNull(tokenUri, "tokenUri is null");
    }

    public Optional<AuthenticationToken> obtainToken(RetryPolicy<TokenPoll> retryPolicy, Duration maxPollingTime, RedirectHandler handler, Tokens tokens)
    {
        requireNonNull(retryPolicy, "retryPolicy is null");
        requireNonNull(maxPollingTime, "maxPollingTime is null");
        requireNonNull(handler, "handler is null");
        requireNonNull(tokens, "prestoAuthentications is null");

        redirectUri.ifPresent(handler::redirectTo);

        TokenPoll tokenPoll = Failsafe.with(retryPolicy
                .abortIf(TokenPoll::hasFailed)
                .handleIf(TokenPollException.class::isInstance))
                .get(context -> pollForToken(context, tokens, maxPollingTime));

        tokenPoll.getError()
                .ifPresent(error -> {
                    throw new ClientException(error);
                });

        return tokenPoll.getToken();
    }

    private TokenPoll pollForToken(ExecutionContext context, Tokens tokens, Duration maxPollingTime)
    {
        Duration remainingTime = Duration.succinctDuration(max(maxPollingTime.toMillis() - context.getElapsedTime().toMillis(), 0), MILLISECONDS);
        return Optional.<TokenPoll>ofNullable(context.getLastResult())
                .flatMap(TokenPoll::getNextTokenUri)
                .map(lastUri -> tokens.pollForTokenUntil(lastUri, remainingTime))
                .orElseGet(() -> tokens.pollForTokenUntil(tokenUri, remainingTime));
    }

    @VisibleForTesting
    Optional<URI> getRedirectUri()
    {
        return redirectUri;
    }

    @VisibleForTesting
    URI getTokenUri()
    {
        return tokenUri;
    }
}
