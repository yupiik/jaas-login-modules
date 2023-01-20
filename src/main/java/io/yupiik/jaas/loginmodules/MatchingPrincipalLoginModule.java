/*
 * Copyright (c) 2022-2023 - Yupiik SAS - https://www.yupiik.com
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package io.yupiik.jaas.loginmodules;

import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;

public abstract class MatchingPrincipalLoginModule extends BaseLoginModule {
    private static final Caches CACHES = new Caches();

    protected Set<Principal> matched = new HashSet<>();

    @Override
    protected final List<Principal> doComputePrincipals() {
        return emptyList();
    }

    protected boolean matches() {
        int matchersCount = 0;
        int matchedCount = 0;

        final Set<Principal> principals = parameters.subject.getPrincipals();

        final Object regex = parameters.options.get("matcher.regex");
        if (regex != null) {
            matchersCount++;
            final Pattern pattern = CACHES.patterns.computeIfAbsent(regex.toString(), Pattern::compile);
            final List<Principal> collect = principals.stream().filter(p -> pattern.matcher(p.getName()).matches()).collect(toList());
            matched.addAll(collect);
            if (!collect.isEmpty()) {
                matchedCount++;
            }
        }

        final Object hasName = parameters.options.get("matcher.hasName");
        if (hasName != null) {
            matchersCount++;

            final List<Principal> collect = principals.stream().filter(p -> Objects.equals(hasName, p.getName())).collect(toList());
            matched.addAll(collect);
            if (!collect.isEmpty()) {
                matchedCount++;
            }
        }

        final Object startsWith = parameters.options.get("matcher.startsWith");
        if (startsWith != null) {
            matchersCount++;

            final String str = startsWith.toString();
            final List<Principal> collect = principals.stream().filter(p -> p.getName().startsWith(str)).collect(toList());
            matched.addAll(collect);
            if (!collect.isEmpty()) {
                matchedCount++;
            }
        }

        final Object endsWith = parameters.options.get("matcher.endsWith");
        if (endsWith != null) {
            matchersCount++;

            final String str = endsWith.toString();
            final List<Principal> collect = principals.stream().filter(p -> p.getName().endsWith(str)).collect(toList());
            matched.addAll(collect);
            if (!collect.isEmpty()) {
                matchedCount++;
            }
        }

        final Object count = parameters.options.get("matcher.count");
        if (endsWith != null) {
            matchersCount++;
            if (principals.size() == Integer.parseInt(count.toString())) {
                matchedCount++;
            }
        }

        if (Boolean.parseBoolean(String.valueOf(parameters.options.get("matcher.isNumber")))) {
            matchersCount++;

            final Object minStr = parameters.options.get("matcher.isNumber.min");
            final Object maxStr = parameters.options.get("matcher.isNumber.max");
            final int min = minStr != null ? Integer.parseInt(minStr.toString()) : Integer.MIN_VALUE;
            final int max = maxStr != null ? Integer.parseInt(maxStr.toString()) : Integer.MAX_VALUE;
            final List<Principal> collect = principals.stream().filter(p -> {
                try {
                    final int v = Integer.parseInt(p.getName());
                    return v >= min && v <= max;
                } catch (final NumberFormatException nfe) {
                    return false;
                }
            }).collect(toList());
            matched.addAll(collect);
            if (!collect.isEmpty()) {
                matchedCount++;
            }
        }

        final boolean allRequired = Boolean.parseBoolean(String.valueOf(parameters.options.get("matcher.allRequired")));
        if (allRequired && matchersCount != matchedCount) {
            return false;
        }

        final boolean singleMatchingPrincipal = Boolean.parseBoolean(String.valueOf(parameters.options.get("matcher.singleMatchingPrincipal")));
        if (singleMatchingPrincipal && matched.size() != 1) {
            return false;
        }

        return matchedCount > 0;
    }

    @Override
    public boolean commit() throws LoginException {
        if (!matches()) {
            state.succeeded = false;
        } else {
            state.principals.addAll(computePrincipals());
        }
        return super.commit();
    }

    private static final class Caches {
        private final Map<String, Pattern> patterns = new ConcurrentHashMap<>();
    }
}
