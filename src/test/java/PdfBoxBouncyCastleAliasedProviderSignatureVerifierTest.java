import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import pdfbox.SignatureVerifier;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import static matcher.SignatureResultVerifiedMatcher.failedToVerify;
import static matcher.SignatureResultVerifiedMatcher.verified;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasValue;

/**
 * {@link PdfBoxBouncyCastleSignatureVerifierTest} encounters the following error when verifying Nitro 11 signed PDFs:
 * <pre>
 * org.bouncycastle.cms.CMSException: can't create digest calculator: exception on setup: java.security.NoSuchAlgorithmException: SHA1WITHRSA MessageDigest not available
 * </pre>
 *
 * This applies the strategy suggested here http://stackoverflow.com/a/38872878
 *
 * While this sidesteps the exception, the signature verification fails.
 */
@RunWith(Parameterized.class)
public class PdfBoxBouncyCastleAliasedProviderSignatureVerifierTest extends PdfBoxBouncyCastleSignatureVerifierTest
{
    @Before
    public void setUp()
    {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        provider.addAlgorithm("Alg.Alias.MessageDigest.SHA1WITHRSA", "SHA-1");
        provider.addAlgorithm("Alg.Alias.MessageDigest.1.2.840.113549.1.1.5", "SHA-1");
        signatureVerifier = new SignatureVerifier(provider);
    }

    public PdfBoxBouncyCastleAliasedProviderSignatureVerifierTest(String description, File pdfFixture, boolean valid)
    {
        super(description, pdfFixture, valid);
    }
}
