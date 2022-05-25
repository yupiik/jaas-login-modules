/*
 * Copyright (c) 2022 - Yupiik - https://www.yupiik.com
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

import io.yupiik.jaas.loginmodules.principal.SimplePrincipal;
import org.junit.jupiter.api.Test;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.yupiik.jaas.loginmodules.test.Extractors.principals;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
import static org.junit.jupiter.api.Assertions.assertEquals;

class TypedPrincipalLoginModuleTest {
    @Test
    void run() throws LoginException {
        final Subject subject = new Subject();
        subject.getPrincipals().add(new SimplePrincipal("a1"));

        final Map<String, Object> options = new HashMap<>();
        options.put("delegate.class", StaticLM.class.getName());
        options.put("delegate.configuraton.name", "conf");
        options.put("principal.type", Pcp.class.getName());

        final LoginContext context = new LoginContext(
                "TypedPrincipalLoginModuleTest",
                subject,
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(TypedPrincipalLoginModule.class.getName(), REQUIRED, options)
                        };
                    }
                });
        context.login();
        assertEquals(
                asList(
                        Pcp.class.getName() + "=conf",
                        SimplePrincipal.class.getName() + "=a1"),
                principals(context, p -> p.getClass().getName() + "=" + p.getName()));
    }

    public static class StaticLM extends BaseLoginModule {
        @Override
        protected List<Principal> computePrincipals() {
            return singletonList(new SimplePrincipal(parameters.options.get("name").toString()));
        }
    }

    public static class Pcp extends SimplePrincipal {
        public Pcp(final String name) {
            super(name);
        }
    }
}
