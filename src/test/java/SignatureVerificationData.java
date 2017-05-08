import java.io.File;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

class SignatureVerificationData {
    static final List<Object[]> pkcs7detachedPdfFixtures;
    static final List<Object[]> rsaSha1PdfFixtures;
    static final List<Object[]> pkcs7Sha1PdfFixtures;
    static {
        pkcs7detachedPdfFixtures = Arrays.asList(
            positiveCase("simple text PDF fixture signed by Nitro11 should validate", "text_sigNitro11.2.pdf"),
            positiveCase("signature field PDF fixture signed by Nitro11 should validate", "sigField_sigNitro11.2.pdf"),
            negativeCase("signature field PDF fixture signed by Nitro11 then modified should not validate", "sigField_sigNitro11_modified.3.pdf"),
            positiveCase("simple text PDF fixture signed by Adobe DC should validate", "text_sigAdobeDC.2.pdf"),
            positiveCase("signature field PDF fixture signed by Adobe DC should validate", "sigField_sigAdobeDC.2.pdf"),
            negativeCase("signature field PDF fixture signed by Adobe DC then modified should not validate", "sigField_sigAdobeDC_modified.3.pdf"),
            positiveCase("simple text PDF fixture approval signed by BouncyCastle should validate", "text_sigBCa.2.pdf"),
            positiveCase("signature field PDF fixture approval signed by BouncyCastle should validate", "sigField_sigBCa.2.pdf"),
            negativeCase("signature field PDF fixture approval signed by BouncyCastle then modified should not validate","sigField_sigBCa_modified.3.pdf"),
            positiveCase("simple text PDF fixture certification signed by BouncyCastle should validate", "text_sigBCc.2.pdf"),
            positiveCase("signature field PDF fixture certification signed by BouncyCastle should validate", "sigField_sigBCc.2.pdf"),
            negativeCase("signature field PDF fixture certification signed by BouncyCastle then modified should not validate", "sigField_sigBCc_modified.3.pdf")
        );

        pkcs7Sha1PdfFixtures = Arrays.asList(
            positiveCase("signature field PDF fixture signed by Adobe DC using pkcs7.sha1 should validate", "sigFieldPkcs7Sha1_sigAdobeDC.2.pdf"),
            negativeCase("signature field PDF fixture signed by Adobe DC using pkcs7.sha1 then modified should not validate", "sigFieldPkcs7Sha1_sigAdobeDC_modified.3.pdf"),
            // This fixture was retrieved from mkl's github repo supporting stackoverflow answers
            positiveCase("adbe.pkcs7.sha1 PDF fixture should validate", "mkl", "SignatureVlidationTest_adbe_pkcs7_sha1.pdf")
        );

        rsaSha1PdfFixtures = Arrays.asList(
            // Note that when creating this fixture, the following error was reported by Adobe:
            // Error storing signature property for the selected signature formatError storing signature property for the selected signature format
            // None the less Adobe Reader DC could subsequently open it and verify it
            positiveCase("signature field PDF fixture signed by Adobe DC using RSA_SHA1 should validate", "sigFieldRsaSha1_sigAdobeDC.2.pdf"),
            negativeCase("signature field PDF fixture signed by Adobe DC using RSA_SHA1 then modified should not validate", "sigFieldRsaSha1_sigAdobeDC_modified.3.pdf")
        );
    }

    protected final String description;
    protected final File pdfFixture;
    protected final boolean valid;

    public SignatureVerificationData(String description, File pdfFixture, boolean valid)
    {
        this.description = description;
        this.pdfFixture = pdfFixture;
        this.valid = valid;
    }

    private static Object[] positiveCase(String description, String... fixturePathUnderTestResources)
    {
        return new Object[]{ description, testPdfFile(fixturePathUnderTestResources), true };
    }

    private static Object[] negativeCase(String description, String... fixturePathUnderTestResources)
    {
        return new Object[]{ description, testPdfFile(fixturePathUnderTestResources), false };
    }

    private static File testPdfFile(String... fixturePathUnderTestResources)
    {
        return Paths.get("src","test").resolve(Paths.get("resources", fixturePathUnderTestResources)).toFile();
    }
}
