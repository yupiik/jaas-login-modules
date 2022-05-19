package io.yupiik.jaas.loginmodules.principal;

import java.security.Principal;
import java.util.Objects;

public class SimplePrincipal implements Principal {
    private final String name;

    public SimplePrincipal(final String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean equals(final Object o) {
        return this == o ||
                (SimplePrincipal.class.isInstance(o) && Objects.equals(name, SimplePrincipal.class.cast(o).name));
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }

    @Override
    public String toString() {
        return "simple[" + name + "]";
    }
}
