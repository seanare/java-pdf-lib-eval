package signature;

import java.security.cert.X509Certificate;

/**
 * A simple tuple containing a X.509 certificate found in a PDF, and an summary of whether the signature was successfully verified.
 */
public class SignatureResult {
    private final String signatureFieldName;
    private final X509Certificate certificate;
    private final boolean verified;

    public SignatureResult(X509Certificate certificate, boolean verified)
    {
        this(null, certificate, verified);
    }

    public SignatureResult(String signatureFieldName, X509Certificate certificate, boolean verified)
    {
        this.signatureFieldName = signatureFieldName;
        this.certificate = certificate;
        this.verified = verified;
    }

    public String getSignatureFieldName()
    {
        return signatureFieldName;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public boolean isVerified() {
        return verified;
    }

    @Override
    public String toString()
    {
        StringBuilder buffy = new StringBuilder();
        if (signatureFieldName != null) {
            buffy.append(signatureFieldName);
            buffy.append(" -> ");
        }
        if (certificate != null) {
            buffy.append(certificate.getSubjectDN().getName());
            buffy.append(' ');
        }
        return buffy.append(verified ?"passed verification" : "failed verification").toString();
    }
}