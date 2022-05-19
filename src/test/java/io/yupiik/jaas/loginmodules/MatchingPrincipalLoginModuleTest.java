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
import static java.util.Collections.singletonMap;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MatchingPrincipalLoginModuleTest {
    @Test
    void startsWithOk() throws LoginException {
        final Subject subject = new Subject();
        subject.getPrincipals().add(new SimplePrincipal("a1"));
        final LoginContext context = new LoginContext(
                "MatchingPrincipalLoginModuleTest",
                subject,
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(StaticLM.class.getName(), REQUIRED, singletonMap("matcher.startsWith", "a"))
                        };
                    }
                });
        context.login();
        assertEquals(asList("a1", "test"), principals(context));
    }

    @Test
    void startsWithKo() throws LoginException {
        final Subject subject = new Subject();
        subject.getPrincipals().add(new SimplePrincipal("a"));
        final LoginContext context = new LoginContext(
                "MatchingPrincipalLoginModuleTest",
                subject,
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(StaticLM.class.getName(), REQUIRED, singletonMap("matcher.startsWith", "ab"))
                        };
                    }
                });
        assertThrows(LoginException.class, context::login);
    }

    @Test
    void regexOk() throws LoginException {
        final Subject subject = new Subject();
        subject.getPrincipals().add(new SimplePrincipal("a1"));
        final LoginContext context = new LoginContext(
                "MatchingPrincipalLoginModuleTest",
                subject,
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(StaticLM.class.getName(), REQUIRED, singletonMap("matcher.regex", "a.+"))
                        };
                    }
                });
        context.login();
        assertEquals(asList("a1", "test"), principals(context));
    }

    @Test
    void regexKo() throws LoginException {
        final Subject subject = new Subject();
        subject.getPrincipals().add(new SimplePrincipal("a"));
        final LoginContext context = new LoginContext(
                "MatchingPrincipalLoginModuleTest",
                subject,
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(StaticLM.class.getName(), REQUIRED, singletonMap("matcher.regex", "a.+"))
                        };
                    }
                });
        assertThrows(LoginException.class, context::login);
    }

    @Test
    void numberOk() throws LoginException {
        final Subject subject = new Subject();
        subject.getPrincipals().add(new SimplePrincipal("12345"));
        final LoginContext context = new LoginContext(
                "MatchingPrincipalLoginModuleTest",
                subject,
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(StaticLM.class.getName(), REQUIRED, singletonMap("matcher.isNumber", "true"))
                        };
                    }
                });
        context.login();
        assertEquals(asList("12345", "test"), principals(context));
    }

    @Test
    void numberKo() throws LoginException {
        final Subject subject = new Subject();
        subject.getPrincipals().add(new SimplePrincipal("a"));
        final LoginContext context = new LoginContext(
                "MatchingPrincipalLoginModuleTest",
                subject,
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(StaticLM.class.getName(), REQUIRED, singletonMap("matcher.isNumber", "true"))
                        };
                    }
                });
        assertThrows(LoginException.class, context::login);
    }

    @Test
    void allOk() throws LoginException {
        final Subject subject = new Subject();
        subject.getPrincipals().add(new SimplePrincipal("12345"));

        final Map<String, String> options = new HashMap<>();
        options.put("matcher.isNumber", "true");
        options.put("matcher.regex", "\\p{Digit}+");
        options.put("matcher.allRequired", "true");
        options.put("matcher.singleMatchingPrincipal", "true");

        final LoginContext context = new LoginContext(
                "MatchingPrincipalLoginModuleTest",
                subject,
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(StaticLM.class.getName(), REQUIRED, options)
                        };
                    }
                });
        context.login();
        assertEquals(asList("12345", "test"), principals(context));
    }

    @Test
    void allKo() throws LoginException {
        final Subject subject = new Subject();
        subject.getPrincipals().add(new SimplePrincipal("1234"));

        final Map<String, String> options = new HashMap<>();
        options.put("matcher.isNumber", "true");
        options.put("matcher.regex", "a.+");
        options.put("matcher.allRequired", "true");

        final LoginContext context = new LoginContext(
                "MatchingPrincipalLoginModuleTest",
                subject,
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(StaticLM.class.getName(), REQUIRED, options)
                        };
                    }
                });
        assertThrows(LoginException.class, context::login);
    }

    public static class StaticLM extends MatchingPrincipalLoginModule {
        @Override
        protected List<Principal> computePrincipals() {
            return singletonList(new SimplePrincipal("test"));
        }
    }
}
