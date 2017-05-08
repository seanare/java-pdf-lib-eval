import com.google.common.collect.Iterables;
import org.icepdf.core.exceptions.PDFException;
import org.icepdf.core.exceptions.PDFSecurityException;
import org.icepdf.core.pobjects.Document;
import org.icepdf.core.pobjects.acroform.InteractiveForm;
import org.icepdf.core.pobjects.acroform.signature.SignatureValidator;
import org.icepdf.core.pobjects.acroform.signature.exceptions.SignatureIntegrityException;
import org.icepdf.core.pobjects.annotations.SignatureWidgetAnnotation;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import signature.SignatureResult;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static matcher.SignatureResultVerifiedMatcher.failedToVerify;
import static matcher.SignatureResultVerifiedMatcher.verified;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasValue;

/**
 * Based on http://sventon.icesoft.org/svn/repos/repo/show/icepdf/trunk/icepdf/examples/signatures/src/main/java/org/icepdf/os/examples/signatures
 * /SignatureVerification.java?revision=51458
 */
@RunWith(Parameterized.class)
public class IcePdfSignatureVerificationTest extends SignatureVerificationData
{
    private Map<String, SignatureResult> extractSignatures() throws IOException, PDFException, PDFSecurityException
    {
        Map<String, SignatureResult> result = new HashMap<>();

        Document document = new Document();
        document.setFile(pdfFixture.getAbsolutePath());

        // signatures can be found off the Catalog as InteractiveForms.
        InteractiveForm interactiveForm = document.getCatalog().getInteractiveForm();
        if (interactiveForm != null) {
            List<SignatureWidgetAnnotation> signatureFields = interactiveForm.getSignatureFields();
            // found some signatures!
            if (signatureFields != null) {
                // must be called in order to verify signatures cover full length of document.
                // signatures cover length of document, there could still be an issue with the signature
                // but we know the signature(s) cover all the bytes in the file.
                //interactiveForm.isSignaturesCoverDocumentLength();
                // validate each signature.
                for (SignatureWidgetAnnotation signatureWidgetAnnotation : signatureFields) {
                    SignatureValidator signatureValidator = signatureWidgetAnnotation.getSignatureValidator();

                    boolean validated = false;
                    try {
                        // validate the signature and certificate.
                        signatureValidator.validate();
                        // This is somewhat of an approximation...
                        validated = !signatureValidator.isSignedDataModified();

                    } catch (SignatureIntegrityException e) {
                        System.out.println("Signature failed to validate: " + signatureValidator.toString());
                        e.printStackTrace();
                    }
                    final String sigFieldName = signatureWidgetAnnotation.getFieldDictionary().getPartialFieldName();
                    result.put(sigFieldName,
                            new SignatureResult(sigFieldName, signatureValidator.getSignerCertificate(), validated));
                }
            }
        }
        return result;
    }

    @Test
    public void verifySignature() throws IOException, PDFException, PDFSecurityException
    {
        assertThat(extractSignatures(), hasValue(valid ? verified() : failedToVerify()));
    }

    @Parameterized.Parameters(name = "{index}: {0} : {1}")
    public static Iterable<Object[]> data()
    {
        return Iterables.concat(pkcs7detachedPdfFixtures, pkcs7Sha1PdfFixtures, rsaSha1PdfFixtures);
    }

    public IcePdfSignatureVerificationTest(String description, File pdfFixture, boolean valid)
    {
        super(description, pdfFixture, valid);
    }

    /*
    private static void printValidationSummary(SignatureValidator signatureValidator)
    {
        System.out.println("Singer Info:");
        if (signatureValidator.isCertificateChainTrusted()) {
            System.out.println("   Path validation checks were successful");
        } else {
            System.out.println("   Path validation checks were unsuccessful");
        }
        if (!signatureValidator.isCertificateChainTrusted() || signatureValidator.isRevocation()) {
            System.out.println("   Revocation checking was not performed");
        } else {
            System.out.println("   Signer's certificate is valid and has not been revoked");
        }
        System.out.println("Validity Summary:");
        if (!signatureValidator.isSignedDataModified() && !signatureValidator.isDocumentDataModified()) {
            System.out.println("   Document has not been modified since it was signed");
        } else if (!signatureValidator.isSignedDataModified() && signatureValidator.isDocumentDataModified() && signatureValidator.isSignaturesCoverDocumentLength()) {
            System.out.println("   This version of the document is unaltered but subsequent changes have been made");
        } else if (!signatureValidator.isSignaturesCoverDocumentLength()) {
            System.out.println("   Document has been altered or corrupted sing it was singed");
        }
        if (!signatureValidator.isCertificateDateValid()) {
            System.out.println("   Signers certificate has expired");
        }
        if (signatureValidator.isEmbeddedTimeStamp()) {
            System.out.println("   Signature included an embedded timestamp but it could not be validated");
        } else {
            System.out.println("   Signing time is from the clock on this signer's computer");
        }
        if (signatureValidator.isSelfSigned()) {
            System.out.println("   Document is self signed");
        }
        System.out.println();
    }
    */
}
