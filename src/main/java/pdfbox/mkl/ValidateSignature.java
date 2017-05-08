package pdfbox.mkl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import signature.SignatureResult;

/**
 * @author mkl
 */
public class ValidateSignature
{
    private final File resultFolder;

    public ValidateSignature(File resultFolder)
    {
        this.resultFolder = resultFolder;
    }

    public Map<String, SignatureResult> validateSignaturesImproved(byte[] pdfByte, String signatureFileName) throws IOException, CMSException, OperatorCreationException, GeneralSecurityException
    {
        Map<String, SignatureResult> result = new HashMap<>();
        try (PDDocument pdfDoc = PDDocument.load(pdfByte))
        {
            List<PDSignature> signatures = pdfDoc.getSignatureDictionaries();
            int index = 0;
            for (PDSignature signature : signatures)
            {
                String subFilter = signature.getSubFilter();
                // The PDFBox examples retrieve the contents using:
                //   ((COSString)signature.getCOSObject().getDictionaryObject(COSName.CONTENTS)).getBytes()
                // the mechanism below throws an "IOException: Invalid hex string" for the fixtures that were modified
                // by PDF box.
                byte[] signatureAsBytes = signature.getContents(pdfByte);
                byte[] signedContentAsBytes = signature.getSignedContent(pdfByte);
                System.out.printf("\nSignature # %s (%s)\n", ++index, subFilter);

                dump(signatureFileName, String.format(signatureFileName, index), "Signature contents", signatureAsBytes);

                final CMSSignedData cms;
                if ("adbe.pkcs7.detached".equals(subFilter) || "ETSI.CAdES.detached".equals(subFilter))
                {
                    cms = new CMSSignedData(new CMSProcessableByteArray(signedContentAsBytes), signatureAsBytes);
                }
                else if ("adbe.pkcs7.sha1".equals(subFilter))
                {
                    cms = new CMSSignedData(new ByteArrayInputStream(signatureAsBytes));
                }
                else if ("adbe.x509.rsa.sha1".equals(subFilter) || "ETSI.RFC3161".equals(subFilter))
                {
                    String diag = String.format("!!! SubFilter %s not yet supported.", subFilter);
                    System.out.println(diag);
                    result.put(signature.getName(), SignatureResult.failed(diag));
                    continue;
                }
                else if (subFilter != null)
                {
                    String diag = String.format("!!! Unknown SubFilter %s.", subFilter);
                    System.out.println(diag);
                    result.put(signature.getName(), SignatureResult.failed(diag));
                    continue;
                }
                else
                {
                    String diag = String.format("!!! Missing SubFilter.");
                    System.out.println(diag);
                    result.put(signature.getName(), SignatureResult.failed(diag));
                    continue;
                }

                SignerInformation signerInfo = (SignerInformation) cms.getSignerInfos().getSigners().iterator().next();
                X509CertificateHolder cert = (X509CertificateHolder) cms.getCertificates().getMatches(signerInfo.getSID())
                        .iterator().next();
                SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(provider()).build(cert);

                boolean verifyResult = signerInfo.verify(verifier);
                if (verifyResult)
                    System.out.println("    Signature verification successful.");
                else
                {
                    System.out.println("!!! Signature verification failed!");
                    dump(signatureFileName, String.format(signatureFileName + "-sigAttr.der", index),
                        "Encoded signed attributes", signerInfo.getEncodedSignedAttributes());
                }

                String diag = null;
                if ("adbe.pkcs7.sha1".equals(subFilter))
                {
                    MessageDigest md = MessageDigest.getInstance("SHA1");
                    byte[] calculatedDigest = md.digest(signedContentAsBytes);
                    byte[] signedDigest = (byte[]) cms.getSignedContent().getContent();
                    boolean digestsMatch = Arrays.equals(calculatedDigest, signedDigest);
                    if (digestsMatch)
                        System.out.println(diag = "    Document SHA1 digest matches.");
                    else
                    {
                        System.out.println(diag = "!!! Document SHA1 digest does not match!");
                    }
                }
                result.put(signature.getName(), new SignatureResult(cert, verifyResult, diag));
            }
        }
        return result;
    }

    private void dump(String signatureFileNameBaseFormat, String signatureFileName, String description, byte[] data) throws IOException {
        if (data == null) {
            System.out.printf("    %s is null\n", description);
            return;
        }

        if (signatureFileNameBaseFormat != null) {
            Files.write(new File(resultFolder, signatureFileName).toPath(), data);
            System.out.printf("    %s stored as '%s'.\n", description, signatureFileName);
        }

        System.out.printf("    ==================================================\n", description, signatureFileName);
        System.out.printf("    %s\n", description);
        try (ASN1InputStream bIn = new ASN1InputStream(data)) {
            Object obj;
            try {
                while ((obj = bIn.readObject()) != null) {
                    System.out.println(ASN1Dump.dumpAsString(obj, false));
                }
            } catch (IOException e) {
                if (!e.getMessage().equals("unexpected end-of-contents marker")) {
                    throw e;
                }
            }
        }
    }

    protected Provider provider() { return new BouncyCastleProvider(); }
}
