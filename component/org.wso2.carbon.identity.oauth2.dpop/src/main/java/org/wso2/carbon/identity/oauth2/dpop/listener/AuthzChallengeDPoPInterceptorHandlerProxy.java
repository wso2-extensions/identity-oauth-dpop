package org.wso2.carbon.identity.oauth2.dpop.listener;

import java.text.ParseException;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthzChallengeReqDTO;
import org.wso2.carbon.identity.oauth2.authzChallenge.event.AbstractAuthzChallengeInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.validators.DPoPHeaderValidator;

public class AuthzChallengeDPoPInterceptorHandlerProxy extends AbstractAuthzChallengeInterceptor {

    private static final Log LOG = LogFactory.getLog(AuthzChallengeDPoPInterceptorHandlerProxy.class);
    private final DPoPHeaderValidator dPoPHeaderValidator;

    public AuthzChallengeDPoPInterceptorHandlerProxy(DPoPHeaderValidator dPoPHeaderValidator) {
        this.dPoPHeaderValidator = dPoPHeaderValidator;
    }

    /**
     * Handles the authorize-challenge request by validating the DPoP header.
     *
     * @param requestDTO authorize-challenge request DTO
     * @return thumbprint of the key extracted from the DPoP proof
     * @throws IdentityOAuth2Exception error during DPoP validation or parsing
     */
    @Override
    public String handleAuthzChallengeReq(OAuth2AuthzChallengeReqDTO requestDTO) throws IdentityOAuth2Exception {
        try {
            String dPoPProof = DPoPHeaderValidator.extractDPoPHeader(requestDTO.getHttpRequestHeaders());

            if (StringUtils.isBlank(dPoPProof)) {
                throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                        "DPoP header is required.");
            }

            String consumerKey = requestDTO.getClientId();
            HttpServletRequest request = requestDTO.getHttpServletRequestWrapper();
            String httpMethod = request.getMethod();
            String httpURL = request.getRequestURL().toString();
            if (!dPoPHeaderValidator.isValidDPoPProof(httpMethod, httpURL, dPoPProof)){
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("DPoP proof validation failed, Application ID: %s.", consumerKey));
                }
                throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                        DPoPConstants.INVALID_DPOP_ERROR);
            }
            return Utils.getThumbprintOfKeyFromDpopProof(dPoPProof);
        } catch (ParseException e) {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                    "Error parsing DPoP proof header." , e);
        }
    }
}
