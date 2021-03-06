import com.google.common.collect.Iterables;
import org.junit.Before;
import org.junit.Test;
import pdfbox.SignatureVerifier;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import static matcher.SignatureResultVerifiedMatcher.failedToVerify;
import static org.hamcrest.MatcherAssert.assertThat;
import static matcher.SignatureResultVerifiedMatcher.verified;
import static org.hamcrest.Matchers.*;

import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PdfBoxBouncyCastleSignatureVerifierTest extends SignatureVerificationData
{
    protected SignatureVerifier signatureVerifier;

    @Before
    public void setUp() {
        signatureVerifier = new SignatureVerifier();
    }

    @Test
    public void verifySignature() throws CertificateException, NoSuchAlgorithmException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException
    {
        assertThat(signatureVerifier.extractSignatures(pdfFixture), hasValue(valid ? verified() : failedToVerify()));
    }

    @Parameterized.Parameters(name = "{index}: {0} : {1}")
    public static Iterable<Object[]> data()
    {
        return Iterables.concat(pkcs7detachedPdfFixtures, pkcs7Sha1PdfFixtures);
    }

    public PdfBoxBouncyCastleSignatureVerifierTest(String description, File pdfFixture, boolean valid)
    {
        super(description, pdfFixture, valid);
    }
}
