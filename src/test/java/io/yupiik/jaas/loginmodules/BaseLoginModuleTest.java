package io.yupiik.jaas.loginmodules;

import io.yupiik.jaas.loginmodules.factory.PrincipalFactory;
import org.junit.jupiter.api.Test;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.util.List;

import static io.yupiik.jaas.loginmodules.test.Extractors.principals;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
import static org.junit.jupiter.api.Assertions.assertEquals;

class BaseLoginModuleTest {
    @Test
    void success() throws LoginException {
        final LoginContext context = new LoginContext(
                "DeducedPrincipalsLoginModulesTest",
                new Subject(),
                null,
                new Configuration() {
                    @Override
                    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
                        return new AppConfigurationEntry[]{
                                new AppConfigurationEntry(LM.class.getName(), REQUIRED, emptyMap())
                        };
                    }
                });
        context.login();
        assertEquals(singletonList("test"), principals(context));
    }

    public static class LM extends BaseLoginModule {
        @Override
        protected List<Principal> computePrincipals() {
            return singletonList(PrincipalFactory.create( // just to show how to use it
                    String.class.cast(parameters.options.get("userPrincipalClass")),
                    "test"));
        }
    }
}
