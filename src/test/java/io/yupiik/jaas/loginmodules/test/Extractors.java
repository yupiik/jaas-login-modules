package io.yupiik.jaas.loginmodules.test;

import javax.security.auth.login.LoginContext;
import java.security.Principal;
import java.util.List;

import static java.util.stream.Collectors.toList;

public final class Extractors {
    private Extractors() {
        // no-op
    }

    public static List<String> principals(final LoginContext context) {
        return context.getSubject().getPrincipals().stream()
                .map(Principal::getName)
                .sorted()
                .collect(toList());
    }
}
