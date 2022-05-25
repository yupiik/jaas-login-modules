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
