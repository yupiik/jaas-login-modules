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

import io.yupiik.jaas.loginmodules.factory.PrincipalFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.lang.reflect.InvocationTargetException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

public class TypedPrincipalLoginModule implements LoginModule {
    private LoginModule delegate;
    private Function<Principal, Principal> principalFactory;
    private boolean removeWrapped;
    private Subject subject;

    @Override
    public void initialize(final Subject subject, final CallbackHandler callbackHandler,
                           final Map<String, ?> sharedState, final Map<String, ?> options) {
        this.subject = subject;
        this.principalFactory = pcp -> PrincipalFactory.create(String.valueOf(options.get("principal.type")).trim(), pcp.getName());
        this.removeWrapped = ofNullable(options.get("removeWrapped")).map(Object::toString).map(Boolean::parseBoolean).orElse(true);
        try {
            this.delegate = ConditionalDelegatingLoginModule.class.getClassLoader()
                    .loadClass(String.valueOf(options.get("delegate.class")).trim())
                    .asSubclass(LoginModule.class)
                    .getConstructor()
                    .newInstance();

            final Map<String, Object> delegateOptions = new HashMap<>(filterByPrefix("delegate.configuration.", options)); // backward compat
            delegateOptions.putAll(filterByPrefix("delegate.configuraton.", options));

            this.delegate.initialize(subject, callbackHandler, sharedState, delegateOptions);
        } catch (final InstantiationException | IllegalAccessException | NoSuchMethodException |
                       ClassNotFoundException e) {
            throw new IllegalStateException(e);
        } catch (final InvocationTargetException e) {
            final Throwable targetException = e.getTargetException();
            if (RuntimeException.class.isInstance(targetException)) {
                throw RuntimeException.class.cast(targetException);
            }
            throw new IllegalStateException(targetException);
        }
    }

    @Override
    public boolean login() throws LoginException {
        return delegate != null && delegate.login();
    }

    @Override
    public boolean commit() throws LoginException {
        final Set<Principal> principals = subject.getPrincipals();
        final Collection<Principal> existing = new ArrayList<>(principals);
        final boolean ok = delegate != null && delegate.commit();
        if (ok && !subject.isReadOnly()) {
            final Collection<Principal> toWrap = new ArrayList<>(principals);
            toWrap.removeAll(existing);
            if (!toWrap.isEmpty()) {
                if (removeWrapped) {
                    toWrap.forEach(principals::remove); // removeAll is often slower, see java.util.AbstractCollection.removeAll()
                }
                principals.addAll(toWrap.stream().map(principalFactory).collect(toList()));
            }
        }
        return ok;
    }

    @Override
    public boolean abort() throws LoginException {
        return delegate != null && delegate.abort();
    }

    @Override
    public boolean logout() throws LoginException {
        return delegate != null && delegate.logout();
    }

    private Map<String, ?> filterByPrefix(final String prefix, final Map<String, ?> options) {
        return options.entrySet().stream()
                .filter(it -> it.getKey().startsWith(prefix))
                .collect(toMap(e -> e.getKey().substring(prefix.length()), Map.Entry::getValue));
    }
}
