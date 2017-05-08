package signature;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * A simple tuple containing a X.509 certificate found in a PDF, and an summary of whether the signature was successfully verified.
 */
public class SignatureResult {
    private final String signatureFieldName;
    private final X509Certificate certificate;
    private final boolean verified;
    private final String diagMessage;

    public SignatureResult(X509Certificate certificate, boolean verified)
    {
        this(null, certificate, verified, null);
    }

    public SignatureResult(String signatureFieldName, X509Certificate certificate, boolean verified)
    {
        this(signatureFieldName, certificate, verified, null);
    }

    public SignatureResult(X509Certificate certificate, boolean verified, String diagMessage)
    {
        this(null, certificate, verified, diagMessage);
    }

    public SignatureResult(X509CertificateHolder certificateHolder, boolean verified, String diagMessage) throws CertificateException {
        this(null, new JcaX509CertificateConverter().getCertificate(certificateHolder), verified, diagMessage);
    }

    public SignatureResult(String signatureFieldName, X509Certificate certificate, boolean verified, String diagMessage)
    {
        this.signatureFieldName = signatureFieldName;
        this.certificate = certificate;
        this.verified = verified;
        this.diagMessage = diagMessage;
    }

    public static SignatureResult failed(String diagMessage)
    {
        return new SignatureResult(null, null, false, diagMessage);
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

    public String getDiagMessage() { return diagMessage; }

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
        buffy.append(verified ?"passed verification" : "failed verification");
        if (diagMessage != null) {
            buffy.append(": ").append(diagMessage);
        }
        return buffy.toString();
    }
}