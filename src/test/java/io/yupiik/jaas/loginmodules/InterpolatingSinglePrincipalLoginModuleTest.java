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
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
import static org.junit.jupiter.api.Assertions.assertEquals;

class InterpolatingSinglePrincipalLoginModuleTest {
    @Test
    void ok() throws LoginException {
        final Map<String, Object> options = new HashMap<>();
        options.put("matcher.regex", ".+");
        options.put("interpolation.pattern", "group_{name}");

        final LoginContext context = new LoginContext(
                "InterpolatingSinglePrincipalLoginModuleTest",
                new Subject(),
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(
                                        ProvidingA1PrincipalLM.class.getName(),
                                        REQUIRED,
                                        emptyMap()),
                                new AppConfigurationEntry(
                                        InterpolatingSinglePrincipalLoginModule.class.getName(),
                                        OPTIONAL,
                                        options)
                        };
                    }
                });
        context.login();
        assertEquals(asList("a1", "group_a1"), principals(context));
    }

    @Test
    void ko() throws LoginException {
        final Map<String, Object> options = new HashMap<>();
        options.put("matcher.regex", "b.+");
        options.put("interpolation.pattern", "group_{name}");

        final LoginContext context = new LoginContext(
                "InterpolatingSinglePrincipalLoginModuleTest",
                new Subject(),
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(
                                        ProvidingA1PrincipalLM.class.getName(),
                                        REQUIRED,
                                        emptyMap()),
                                new AppConfigurationEntry(
                                        InterpolatingSinglePrincipalLoginModule.class.getName(),
                                        OPTIONAL,
                                        options)
                        };
                    }
                });
        context.login();
        assertEquals(singletonList("a1"), principals(context));
    }

    public static class ProvidingA1PrincipalLM extends BaseLoginModule {
        @Override
        protected List<Principal> computePrincipals() {
            return singletonList(new SimplePrincipal("a1"));
        }
    }
}
