package io.yupiik.jaas.loginmodules;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static java.util.Collections.emptyList;

public class ConditionalDelegatingLoginModule extends MatchingPrincipalLoginModule {
    private Supplier<LoginModule> factory;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        factory = () -> {
            LoginModule delegate;
            try {
                delegate = ConditionalDelegatingLoginModule.class.getClassLoader()
                        .loadClass(String.valueOf(parameters.options.get("delegate.class")).trim())
                        .asSubclass(LoginModule.class)
                        .getConstructor()
                        .newInstance();
            } catch (final Exception ex) {
                throw new IllegalStateException(ex);
            }
            delegate.initialize(subject, callbackHandler, sharedState, options);
            return delegate;
        };
    }

    @Override
    protected List<Principal> computePrincipals() throws LoginException {
        final LoginModule delegate = factory.get();
        try {
            delegate.login();
            delegate.commit();
            return emptyList(); // delegate will patch the subject
        } catch (final LoginException le) {
            try {
                delegate.abort();
            } catch (final LoginException le2) {
                // no-op, use previous one
            }
            throw le;
        }
    }
}
