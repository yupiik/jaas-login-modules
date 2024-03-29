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

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyMap;

public abstract class BaseLoginModule implements LoginModule {
    protected final Parameters parameters = new Parameters();
    protected final State state = new State();

    protected abstract List<Principal> computePrincipals() throws LoginException;

    protected List<Principal> doComputePrincipals() throws LoginException {
        return computePrincipals();
    }

    @Override
    public void initialize(final Subject subject,
                           final CallbackHandler callbackHandler,
                           final Map<String, ?> sharedState,
                           final Map<String, ?> options) {
        this.parameters.subject = subject;
        this.parameters.options = new HashMap<>(options == null ? emptyMap() : options);
    }

    @Override
    public boolean login() throws LoginException {
        if (parameters.subject.isReadOnly()) {
            return false;
        }
        state.principals.addAll(doComputePrincipals());
        state.succeeded = true;
        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        if (!state.succeeded) {
            return false;
        }
        parameters.subject.getPrincipals().addAll(state.principals);
        state.commitSucceeded = true;
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        if (!state.succeeded) {
            return false;
        }
        if (state.commitSucceeded) {
            logout();
        } else {
            state.succeeded = false;
        }
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        if (!parameters.subject.isReadOnly()) {
            parameters.subject.getPrincipals().removeAll(state.principals);
        }
        state.succeeded = false;
        state.commitSucceeded = false;
        return true;
    }


    protected static final class Parameters {
        protected Map<String, Object> options;
        protected Subject subject;
    }

    protected static final class State {
        protected boolean succeeded;
        protected boolean commitSucceeded;
        protected final List<Principal> principals = new ArrayList<>();
    }
}
