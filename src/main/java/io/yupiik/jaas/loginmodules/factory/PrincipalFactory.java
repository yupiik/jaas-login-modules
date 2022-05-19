package io.yupiik.jaas.loginmodules.factory;

import io.yupiik.jaas.loginmodules.principal.SimplePrincipal;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Principal;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

public final class PrincipalFactory {
    private static final Map<String, Function<String, Principal>> FACTORIES = new ConcurrentHashMap<>();

    private PrincipalFactory() {
        // no-op
    }

    // type can be
    // - org.apache.activemq.jaas.UserPrincipal, org.apache.activemq.jaas.GroupPrincipal for AMQ
    // - org.apache.openejb.core.security.jaas.UserPrincipal, org.apache.openejb.core.security.jaas.GroupPrincipal for TomEE
    // - etc
    // the constraint is to have a constructor taking a single string (name of the principal)
    public static Principal create(final String type, final String principalName) {
        return FACTORIES.computeIfAbsent(type == null ? "" : type, t -> {
            if (t.trim().isEmpty()) {
                return SimplePrincipal::new;
            }

            try {
                final Constructor<? extends Principal> constructor = PrincipalFactory.class.getClassLoader()
                        .loadClass(t.trim())
                        .asSubclass(Principal.class)
                        .getConstructor(String.class);
                return name -> {
                    try {
                        return constructor.newInstance(name);
                    } catch (final InvocationTargetException e) {
                        final Throwable targetException = e.getTargetException();
                        if (RuntimeException.class.isInstance(targetException)) {
                            throw RuntimeException.class.cast(targetException);
                        }
                        throw new IllegalStateException(targetException);
                    } catch (final Exception e) {
                        throw new IllegalArgumentException("unsupported principal type: '" + t + "'", e);
                    }
                };
            } catch (final Exception e) {
                throw new IllegalArgumentException("unsupported principal type: '" + t + "'", e);
            }
        }).apply(principalName);
    }
}
