
import java.io.*;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.Security;

import com.google.common.collect.Iterables;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import pdfbox.SignatureVerifier;
import pdfbox.mkl.ValidateSignature;

import static matcher.SignatureResultVerifiedMatcher.failedToVerify;
import static matcher.SignatureResultVerifiedMatcher.verified;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasValue;

@RunWith(Parameterized.class)
public class PdfBoxMklValidateSignatureTest extends SignatureVerificationData
{
    final static boolean ALIAS_SHA1WITHRSA = true;
    final static File RESULT_FOLDER = Paths.get("src","test", "resources", "test-outputs").toFile();
    ValidateSignature validateSignature;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        RESULT_FOLDER.mkdirs();
    }

    @Before
    public void setUp()
    {
        if (ALIAS_SHA1WITHRSA) {
            validateSignature = new ValidateSignature(RESULT_FOLDER) {
                @Override
                protected Provider provider() {
                    BouncyCastleProvider provider = new BouncyCastleProvider();
                    provider.addAlgorithm("Alg.Alias.MessageDigest.SHA1WITHRSA", "SHA-1");
                    provider.addAlgorithm("Alg.Alias.MessageDigest.1.2.840.113549.1.1.5", "SHA-1");
                    return provider;
                }
            };
        } else {
            validateSignature = new ValidateSignature(RESULT_FOLDER);
        }
    }

    @Test
    public void validateSignature() throws Exception
    {
        try (InputStream resource = new FileInputStream(pdfFixture))
        {
            assertThat(validateSignature.validateSignaturesImproved(IOUtils.toByteArray(resource), pdfFixture.getName() + "-%s.cms"),
                       hasValue(valid ? verified() : failedToVerify()));
        }
    }

    @Parameterized.Parameters(name = "{index}: {0} : {1}")
    public static Iterable<Object[]> data()
    {
        return Iterables.concat(pkcs7detachedPdfFixtures, pkcs7Sha1PdfFixtures, rsaSha1PdfFixtures);
    }

    public PdfBoxMklValidateSignatureTest(String description, File pdfFixture, boolean valid)
    {
        super(description, pdfFixture, valid);
    }
}
