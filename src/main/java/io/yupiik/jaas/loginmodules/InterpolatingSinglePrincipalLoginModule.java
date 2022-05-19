package io.yupiik.jaas.loginmodules;

import io.yupiik.jaas.loginmodules.factory.PrincipalFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import java.security.Principal;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;

public class InterpolatingSinglePrincipalLoginModule extends MatchingPrincipalLoginModule {
    @Override
    public void initialize(final Subject subject, final CallbackHandler callbackHandler,
                           final Map<String, ?> sharedState, final Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        this.parameters.options.put("matcher.singleMatchingPrincipal", "true");
    }

    @Override
    protected List<Principal> computePrincipals() {
        final Object type = this.parameters.options.get("interpolation.principal.type");
        return singletonList(PrincipalFactory.create(
                type == null ? null : type.toString(),
                this.parameters.options.get("interpolation.pattern").toString().replace("{name}", matched.iterator().next().getName())));
    }
}
