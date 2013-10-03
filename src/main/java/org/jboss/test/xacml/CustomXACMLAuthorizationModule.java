/*
 * Copyright 2013, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.test.xacml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceKeys;
import org.jboss.security.authorization.modules.AbstractAuthorizationModule;
import org.jboss.security.authorization.modules.XACMLAuthorizationModule;
import org.jboss.security.authorization.modules.ejb.EJBXACMLUtil;
import org.jboss.security.authorization.modules.web.WebXACMLUtil;
import org.jboss.security.authorization.resources.EJBResource;
import org.jboss.security.authorization.resources.WebResource;
import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;

/**
 * A custom XACML authorization module, which emulates behavior of {@link XACMLAuthorizationModule}. This class helps test usage
 * of a custom authorization module for web applications and EJBs. It also checks integration of XACML authorization routines
 * (workaround for an issue JBPAPP-8773).
 * 
 * @author Josef Cacek
 */
public class CustomXACMLAuthorizationModule extends AbstractAuthorizationModule {
    private static final Logger LOGGER = Logger.getLogger(CustomXACMLAuthorizationModule.class);

    private final JBossPDP pdp;

    // Constructors ----------------------------------------------------------

    /**
     * Create a new CustomXACMLAuthorizationModule instance. It creates a single {@link JBossPDP} instance, which loads its
     * configuration from /jbossxacml-config.xml file on the classpath.
     */
    public CustomXACMLAuthorizationModule() {
        LOGGER.debug("Creating new instance of the custom authorization module");
        try {
            pdp = new JBossPDP(getClass().getResourceAsStream("/jbossxacml-config.xml"));
        } catch (RuntimeException e) {
            LOGGER.error("PDP initialization failed.", e);
            throw e;
        }
    }

    // Public methods --------------------------------------------------------

    /**
     * Implements XACML based authorization for {@link WebResource} and {@link EJBResource}.
     * 
     * @param resource
     * @return
     * @see org.jboss.security.authorization.modules.AbstractAuthorizationModule#authorize(org.jboss.security.authorization.Resource)
     */
    @Override
    public int authorize(Resource resource) {
        LOGGER.info("Authorizing resource: " + resource);
        int result = AuthorizationContext.DENY;

        if (resource instanceof WebResource) {
            LOGGER.debug("WebResource authorization");
            result = authorizeWebResource((WebResource) resource);
        } else if (resource instanceof EJBResource) {
            LOGGER.debug("EJBResource authorization");
            result = authorizeEJBResource((EJBResource) resource);
        }
        return result;
    }

    // Private methods -------------------------------------------------------

    /**
     * Authorizes the {@link WebResource} instance.
     * 
     * @param webResource
     * @return
     */
    private int authorizeWebResource(WebResource webResource) {
        int result = AuthorizationContext.DENY;
        // Get the contextual map
        Map<String, Object> map = webResource.getMap();
        if (map == null || map.size() == 0) {
            throw new IllegalStateException("Map from the Resource is empty.");
        }

        // If it is a userDataCheck or a RoleRefCheck, then the base class (RealmBase) decision holds
        if (Boolean.TRUE.equals(map.get(ResourceKeys.USERDATA_PERM_CHECK))
                || Boolean.TRUE.equals(map.get(ResourceKeys.ROLEREF_PERM_CHECK)))
            return AuthorizationContext.PERMIT; // Base class decision holds good

        final HttpServletRequest request = (HttpServletRequest) webResource.getServletRequest();
        if (request == null)
            throw new IllegalStateException("HttpServletRequest is null");

        final Principal userP = request.getUserPrincipal();
        if (userP == null)
            throw new IllegalStateException("User Principal is null");

        final WebXACMLUtil util = new WebXACMLUtil();
        try {
            final RequestContext requestCtx = util.createXACMLRequest(request, role);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(toString(requestCtx));
            }
            final ResponseContext response = pdp.evaluate(requestCtx);
            result = response.getDecision() == XACMLConstants.DECISION_PERMIT ? AuthorizationContext.PERMIT
                    : AuthorizationContext.DENY;
        } catch (Exception e) {
            LOGGER.warn("Exception in processing:", e);
        }
        return result;
    }

    /**
     * Authorizes {@link EJBResource} instance.
     * 
     * @param ejbResource
     * @return
     */
    private int authorizeEJBResource(EJBResource ejbResource) {
        int result = AuthorizationContext.DENY;

        // Get the contextual map
        Map<String, Object> map = ejbResource.getMap();
        if (map == null || map.size() == 0) {
            throw new IllegalStateException("Map from the Resource is empty.");
        }

        if (Boolean.TRUE.equals(map.get(ResourceKeys.ROLEREF_PERM_CHECK))) {
            // Don't do this in the real world!
            return AuthorizationContext.PERMIT;
        }
        final EJBXACMLUtil util = new EJBXACMLUtil();
        try {
            final RequestContext requestCtx = util.createXACMLRequest(ejbResource.getEjbName(), ejbResource.getEjbMethod(),
                    ejbResource.getPrincipal(), role);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(toString(requestCtx));
            }
            final ResponseContext response = pdp.evaluate(requestCtx);
            result = response.getDecision() == XACMLConstants.DECISION_PERMIT ? AuthorizationContext.PERMIT
                    : AuthorizationContext.DENY;
        } catch (Exception e) {
            LOGGER.error("Exception in processing:", e);
            result = AuthorizationContext.DENY;
        }
        return result;
    }

    /**
     * Returns the given {@link RequestContext} marshaled into a String.
     * 
     * @param requestCtx
     * @return
     * @throws IOException
     * @throws UnsupportedEncodingException
     */
    private String toString(final RequestContext requestCtx) throws IOException, UnsupportedEncodingException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        requestCtx.marshall(baos);
        final String requestCtxStr = baos.toString("UTF-8");
        return requestCtxStr;
    }

}
