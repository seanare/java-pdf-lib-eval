import java.io.File;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

class SignatureVerificationData {
    protected static final List<Object[]> pdfFixtures;
    static {
        pdfFixtures = Arrays.asList(
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
            // Note that when creating this fixture, the following error was reported by Adobe:
            // Error storing signature property for the selected signature formatError storing signature property for the selected signature format
            // None the less Adobe Reader DC could subsequently open it and verify it
            //positiveCase("signature field PDF fixture certification signed by Adobe DC using RSA_SHA1 should validate", "sigFieldRsaSha1_sigAdobeDC.2.pdf")
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

    private static Object[] positiveCase(String description, String fixtureFileInTestResources)
    {
        return new Object[]{ description, testPdfFile(fixtureFileInTestResources), true };
    }

    private static Object[] negativeCase(String description, String fixtureFileInTestResources)
    {
        return new Object[]{ description, testPdfFile(fixtureFileInTestResources), false };
    }

    private static File testPdfFile(String path, String... more)
    {
        return Paths.get("src", "test", "resources").resolve(Paths.get(path, more)).toFile();
    }
}
