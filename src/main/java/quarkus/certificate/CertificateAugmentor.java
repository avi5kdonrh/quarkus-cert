package quarkus.certificate;

import io.quarkus.security.ForbiddenException;
import io.quarkus.security.credential.CertificateCredential;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.identity.request.AnonymousAuthenticationRequest;
import io.quarkus.security.runtime.AnonymousIdentityProvider;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class CertificateAugmentor implements SecurityIdentityAugmentor {

    Logger logger = LoggerFactory.getLogger(CertificateCredential.class);
    @Override
    public Uni<SecurityIdentity> augment(SecurityIdentity identity, AuthenticationRequestContext context) {

        CertificateCredential certificate = identity.getCredential(CertificateCredential.class);
        if ( certificate != null ) {


            if (!certificate.getCertificate().getSubjectX500Principal().getName().equals("CN=xyz")) {
                logger.error("Exception :: Invalid CN");
                return Uni.createFrom().failure(new ForbiddenException());
            }
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                    .setPrincipal(certificate.getCertificate().getSubjectX500Principal())
                    .addCredential(certificate)
                    .build());

        }
       return new AnonymousIdentityProvider().authenticate(new AnonymousAuthenticationRequest(),context);

    }



}