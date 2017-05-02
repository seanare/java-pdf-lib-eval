package fixture;

import fixture.pdfboxeg.CreateSignature;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSeedValue;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;
import org.junit.Ignore;
import org.junit.Test;
import static org.junit.Assume.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Collections;

public class GeneratePDFFixtures
{
    @Test public void generateFixture_text_sigNitro11() throws IOException, GeneralSecurityException
    {
        generateSimplePdfText(testResources("text_sigNitro11.1.pdf"),
            "PDF fixture",
            "1. Simple text only PDF generated using PDFBox",
            "2. Signed manually using Nitro Pro 11"
        );
    }

    @Test public void generateFixture_sigField_sigNitro11() throws IOException, GeneralSecurityException
    {
        generateSimplePdfWithSignatureField(testResources("sigField_sigNitro11.1.pdf"),
            "PDF fixture",
            "1. Simple PDF with signature field generated using PDFBox",
            "2. Signed manually using Nitro Pro 11"
        );
    }

    @Test public void generateFixture_sigField_sigNitro11_modified() throws IOException, GeneralSecurityException, URISyntaxException
    {
        modifyPdf(testResources("sigField_sigNitro11.2.pdf"), testResources("sigField_sigNitro11_modified.3.pdf"), 3, "3. Modified with PDFBox");
    }

    @Test public void generateFixture_text_sigAdobeDC() throws IOException, GeneralSecurityException
    {
        generateSimplePdfText(testResources("text_sigAdobeDC.1.pdf"),
                "PDF fixture",
                "1. Simple text only PDF generated using PDFBox",
                "2. Signed manually using Adobe Reader DC"
        );
    }

    @Test public void generateFixture_sigField_sigAdobeDC() throws IOException, GeneralSecurityException
    {
        generateSimplePdfWithSignatureField(testResources("sigField_sigAdobeDC.1.pdf"),
                "PDF fixture",
                "1. Simple PDF with signature field generated using PDFBox",
                "2. Signed manually using Adobe Reader DC"
        );
    }

    @Test public void generateFixture_sigField_sigAdobeDC_modified() throws IOException, GeneralSecurityException, URISyntaxException
    {
        modifyPdf(testResources("sigField_sigAdobeDC.2.pdf"), testResources("sigField_sigAdobeDC_modified.3.pdf"), 3, "3. Modified with PDFBox");
    }

    @Test public void generateFixture_sigFieldRsaSha1_sigAdobeDC() throws IOException, GeneralSecurityException
    {
        generateSimplePdfWithOptionalSignatureFieldOptionalSig(testResources("sigFieldRsaSha1_sigAdobeDC.1.pdf"), SignatureField.RSA_SHA1,
                "PDF fixture",
                "1. Simple PDF with signature field requesting adbe.x509.rsa_sha1 SubFilter generated using PDFBox",
                "2. Signed manually using Adobe Reader DC"
        );
    }

    @Test public void generateFixture_text_sigBCa() throws IOException, GeneralSecurityException
    {
        signPdf(generateSimplePdfText(testResources("text_sigBCa.1.pdf"),
                "PDF fixture",
                "1. Simple text only PDF generated using PDFBox",
                "2. Signed (approval) non-visually using PDFBox and BouncyCastle"
        ), testResources("text_sigBCa.2.pdf"), false);
    }

    @Test public void generateFixture_sigField_sigBCa() throws IOException, GeneralSecurityException
    {
        signPdf(generateSimplePdfWithSignatureField(testResources("sigField_sigBCa.1.pdf"),
                "PDF fixture",
                "1. Simple PDF with signature field generated using PDFBox",
                "2. Signed (approval) non-visually using PDFBox and BouncyCastle"
        ), testResources("sigField_sigBCa.2.pdf"), false);
    }

    @Test public void generateFixture_sigField_sigBCa_modified() throws IOException, GeneralSecurityException, URISyntaxException
    {
        modifyPdf(testResources("sigField_sigBCa.2.pdf"), testResources("sigField_sigBCa_modified.3.pdf"), 3, "3. Modified with PDFBox");
    }

    @Test public void generateFixture_text_sigBCc() throws IOException, GeneralSecurityException {
        signPdf(generateSimplePdfText(testResources("text_sigBCc.1.pdf"),
                "PDF fixture",
                "1. Simple text only PDF generated using PDFBox",
                "2. Signed (certify) non-visually using PDFBox and BouncyCastle"
        ), testResources("text_sigBCc.2.pdf"), true);
    }

    @Test public void generateFixture_sigField_sigBCc() throws IOException, GeneralSecurityException
    {
        signPdf(generateSimplePdfWithSignatureField(testResources("sigField_sigBCc.1.pdf"),
                "PDF fixture",
                "1. Simple PDF with signature field generated using PDFBox",
                "2. Signed (certify) non-visually using PDFBox and BouncyCastle"
        ), testResources("sigField_sigBCc.2.pdf"), true);
    }

    @Test public void generateFixture_sigField_sigBCc_modified() throws IOException, GeneralSecurityException, URISyntaxException
    {
        modifyPdf(testResources("sigField_sigBCc.2.pdf"), testResources("sigField_sigBCc_modified.3.pdf"), 3, "3. Modified with PDFBox");
    }

    private Path generateSimplePdfText(Path pdfFixtureOutput, String... lines) throws IOException, GeneralSecurityException
    {
        return generateSimplePdfWithOptionalSignatureFieldOptionalSig(pdfFixtureOutput, SignatureField.NONE, lines);
    }

    private Path generateSimplePdfWithSignatureField(Path pdfFixtureOutput, String... lines) throws IOException, GeneralSecurityException
    {
        return generateSimplePdfWithOptionalSignatureFieldOptionalSig(pdfFixtureOutput, SignatureField.SIMPLE, lines);
    }

    private enum SignatureField
    {
        NONE(false),
        SIMPLE(true),
        RSA_SHA1(true, COSName.ADBE_X509_RSA_SHA1);
        //PKCS7_DETACHED(true, COSName.ADBE_PKCS7_DETACHED);

        final boolean includeSignatureField;
        final COSName subFilterSeedValue;

        SignatureField(boolean includeSignatureField)
        {
            this(includeSignatureField, null);
        }

        SignatureField(boolean includeSignatureField, COSName subFilterSeedValue)
        {
            this.includeSignatureField = includeSignatureField;
            this.subFilterSeedValue = subFilterSeedValue;
        }
    }

    /**
     * This is based on a simple merge of http://stackoverflow.com/a/19683618
     * https://github.com/mkl-public/testarea-pdfbox2/blob/master/src/test/java/mkl/testarea/pdfbox2/content/BreakLongString.java#L39
     * and
     * https://svn.apache.org/viewvc/pdfbox/trunk/examples/src/main/java/org/apache/pdfbox/examples/signature/CreateEmptySignatureForm.java?view=markup
     */
    private Path generateSimplePdfWithOptionalSignatureFieldOptionalSig(final Path pdfFixtureOutput,
             final SignatureField sigField, final String... lines) throws IOException, GeneralSecurityException
    {
        assumeTrue("Target PDF document \"" + pdfFixtureOutput + "\" already exists", Files.notExists(pdfFixtureOutput));

        try (PDDocument doc = new PDDocument()) {
            if (sigField.subFilterSeedValue != null) {
                // Table 232 in section 12.7.4.5 of PDF 32000-1:2008 indicates that SeedValue is supported from PDF 1.5, and PDFBox is defaulting to 1.4
                doc.setVersion(1.5f);
            }

            final PDPage page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            final PDPageContentStream contentStream = new PDPageContentStream(doc, page);

            PDFont pdfFont = PDType1Font.HELVETICA;
            final float fontSize = 14;
            final float leading = 1.5f * fontSize;

            final PDRectangle mediabox = page.getMediaBox();
            final float margin = 72;
            final float startX = mediabox.getLowerLeftX() + margin;
            final float startY = mediabox.getUpperRightY() - margin;

            /* We don't need auto-wrapping for simple fixtures

            float width = mediabox.getWidth() - 2*margin;

            String text = "I am trying to create a PDF file with a lot of text contents in the document. I am using PDFBox";
            List<String> lines = new ArrayList<String>();
            int lastSpace = -1;
            while (text.length() > 0) {
                int spaceIndex = text.indexOf(' ', lastSpace + 1);
                if (spaceIndex < 0) {
                    spaceIndex = text.length();
                }
                String subString = text.substring(0, spaceIndex);
                float size = fontSize * pdfFont.getStringWidth(subString) / 1000;
                System.out.printf("'%s' - %f of %f\n", subString, size, width);
                if (size > width) {
                    if (lastSpace < 0)
                        lastSpace = spaceIndex;
                    subString = text.substring(0, lastSpace);
                    lines.add(subString);
                    text = text.substring(lastSpace).trim();
                    System.out.printf("'%s' is line\n", subString);
                    lastSpace = -1;

                } else if (spaceIndex == text.length()) {
                    lines.add(text);
                    System.out.printf("'%s' is line\n", text);
                    text = "";

                } else {
                    lastSpace = spaceIndex;
                }
            }
            */

            float currentY = startY;

            contentStream.beginText();
            contentStream.setFont(pdfFont, fontSize);
            contentStream.newLineAtOffset(startX, startY);
            for (String line: lines) {
                contentStream.showText(line);
                contentStream.newLineAtOffset(0, -leading);
                currentY -= leading;
            }
            contentStream.endText();
            contentStream.close();

            if (sigField.includeSignatureField) {
                // Add a new AcroForm and add that to the document
                final PDAcroForm acroForm = new PDAcroForm(doc);
                doc.getDocumentCatalog().setAcroForm(acroForm);

                // Acrobat sets the font size on the form level to be
                // auto sized as default. This is done by setting the font size to '0'
                acroForm.setDefaultAppearance("/Helv 0 Tf 0 g");

                // --- end of general AcroForm stuff ---

                PDSignatureField signatureField = new PDSignatureField(acroForm);
                signatureField.setPartialName("ManualSig_1"); // by default the field would be named "Signature1"
                if (sigField.subFilterSeedValue != null) {
                    PDSeedValue seedValue = new PDSeedValue();
                    seedValue.setSubFilter(Collections.singletonList(sigField.subFilterSeedValue));
                    signatureField.setSeedValue(seedValue);
                }
                PDAnnotationWidget widget = signatureField.getWidgets().get(0);
                final float sigFieldHeight = 50;
                PDRectangle rect = new PDRectangle(startX, currentY - sigFieldHeight, 200, sigFieldHeight);
                widget.setRectangle(rect);
                widget.setPage(page);
                page.getAnnotations().add(widget);

                acroForm.getFields().add(signatureField);
            }

            doc.save(pdfFixtureOutput.toFile());

            return pdfFixtureOutput;
        }
    }

    private CreateSignature createSignature() throws GeneralSecurityException, IOException
    {
        final char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (InputStream keyStoreStream = new FileInputStream(testResources("keystore.jks").toFile())) {
            keyStore.load(keyStoreStream, password);
        }

        CreateSignature createSignature = new CreateSignature(keyStore, password);
        createSignature.setExternalSigning(true);
        return createSignature;
    }

    private Path signPdf(final Path sourcePdfName, final Path pdfFixtureOutput, final boolean certify) throws IOException, GeneralSecurityException
    {
        createSignature().signDetached(sourcePdfName.toFile(), pdfFixtureOutput.toFile(), certify);
        return pdfFixtureOutput;
    }

    private Path modifyPdf(final Path sourcePdfName, final Path pdfFixtureOutput, float y, final String modificationText) throws IOException, URISyntaxException
    {
        assumeTrue("Source PDF document \"" + sourcePdfName + "\" does not exist", Files.exists(sourcePdfName));
        assumeTrue("Target PDF document \"" + pdfFixtureOutput + "\" already exists", Files.notExists(pdfFixtureOutput));

        try (PDDocument doc = PDDocument.load(sourcePdfName.toFile())) {

            PDFont pdfFont = PDType1Font.HELVETICA;
            final float fontSize = 14;
            final float leading = 1.5f * fontSize;

            assumeTrue("Source PDF document \"" + sourcePdfName + "\" does not contain any pages", doc.getPages().getCount() > 0);

            PDPage page = doc.getPages().get(0);

            final PDRectangle mediabox = page.getMediaBox();
            final float margin = 72;
            final float startX = mediabox.getLowerLeftX() + margin;
            final float startY = mediabox.getUpperRightY() - margin - (y * leading);

            // append the content to the existing stream
            PDPageContentStream contentStream = new PDPageContentStream(doc, page, PDPageContentStream.AppendMode.APPEND, false, true);
            contentStream.beginText();
            contentStream.setFont(pdfFont, fontSize);
            contentStream.setTextMatrix(Matrix.getTranslateInstance(startX, startY));
            contentStream.showText(modificationText);
            contentStream.endText();
            contentStream.close();

            doc.save(pdfFixtureOutput.toFile());
        }
        return pdfFixtureOutput;
    }

    private static Path testResources(String path, String... more)
    {
        return Paths.get("src", "test", "resources").resolve(Paths.get(path, more));
    }
}
