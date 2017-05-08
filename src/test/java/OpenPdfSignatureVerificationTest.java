import com.google.common.collect.Iterables;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import signature.SignatureResult;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static matcher.SignatureResultVerifiedMatcher.failedToVerify;
import static matcher.SignatureResultVerifiedMatcher.verified;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasValue;

/**
 * Based on https://github.com/cristiroma/pdf.signature/blob/master/ro/edw/pdf/PDFSignature.java
 * and http://www.berthou.com/us/2009/07/01/verify-pdf-signature-with-itext/
 */
@RunWith(Parameterized.class)
public class OpenPdfSignatureVerificationTest extends SignatureVerificationData
{
    @BeforeClass
    public static void setUpClass() {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

    /**
     * Note this maps from the signature field name to the SignatureResult, unlike the PDFBox version, that
     * maps the the signature name to the SignatureResult.
     */
    private Map<String, SignatureResult> extractSignatures() throws IOException, GeneralSecurityException {
        Map<String, SignatureResult> result = new HashMap<>();

        PdfReader reader = new PdfReader(pdfFixture.toURL());
        AcroFields fields = reader.getAcroFields();
        List<String> names = fields.getSignatureNames();
        for (String sigFieldName : names) {
            PdfPKCS7 pkcs7 = fields.verifySignature(sigFieldName);
//            System.out.println("Signature covers whole document: " + fields.signatureCoversWholeDocument(sigFieldName));
//            System.out.println("Document revision: " + fields.getRevision(sigFieldName) + " of " + fields.getTotalRevisions());
            result.put(sigFieldName, new SignatureResult(sigFieldName, pkcs7.getSigningCertificate(), pkcs7.verify()));
        }
        return result;
    }

    @Test
    public void verifySignature() throws IOException, GeneralSecurityException
    {
        assertThat(extractSignatures(), hasValue(valid ? verified() : failedToVerify()));
    }

    @Parameterized.Parameters(name = "{index}: {0} : {1}")
    public static Iterable<Object[]> data()
    {
        return Iterables.concat(pkcs7detachedPdfFixtures, pkcs7Sha1PdfFixtures, rsaSha1PdfFixtures);
    }

    public OpenPdfSignatureVerificationTest(String description, File pdfFixture, boolean valid)
    {
        super(description, pdfFixture, valid);
    }
}
