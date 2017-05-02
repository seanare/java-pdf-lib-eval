package pdfbox;/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

import signature.SignatureResult;

/**
 * Extracts digital signatures from a PDF document using PDFBox and validates PKCS#7
 * signatures using BouncyCastle.
 *
 * A very slight variation on the ShowSignature example by Ben Litchfield:
 * https://svn.apache.org/viewvc/pdfbox/trunk/examples/src/main/java/org/apache/pdfbox/examples/signature/ShowSignature.java?revision=1792241&view=co
 *
 * It is certainly possible in PDFBox to traverse the signatures in a PDF from the fields in the {@link org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm},
 * in which case the signature field name could be included as per other libraries.  However for the purpose of example, this simply follows the
 * underlying sample code as closely as possible to avoid adding noise.
 *
 * @author Ben Litchfield
 */
public final class SignatureVerifier
{
    private final SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
    private final Provider provider;

    public SignatureVerifier()
    {
        this(null);
    }

    public SignatureVerifier(final Provider provider)
    {
        this.provider = provider;
    }

    public Map<String, SignatureResult> extractSignatures(File infile) throws IOException, CertificateException,
                                                     NoSuchAlgorithmException, InvalidKeyException,
                                                     NoSuchProviderException, SignatureException
    {
        Map<String, SignatureResult> result = new HashMap<>();

            try (PDDocument document = PDDocument.load(infile))
            {
                for (PDSignature sig : document.getSignatureDictionaries())
                {
                    COSDictionary sigDict = sig.getCOSObject();
                    COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);

                    // download the signed content
                    byte[] buf;
                    try (FileInputStream fis = new FileInputStream(infile))
                    {
                        buf = sig.getSignedContent(fis);
                    }

                    System.out.println("Signature found");
                    System.out.println("Name:     " + sig.getName());
                    System.out.println("Modified: " + sdf.format(sig.getSignDate().getTime()));
                    String subFilter = sig.getSubFilter();
                    if (subFilter != null)
                    {
                        switch (subFilter)
                        {
                            case "adbe.pkcs7.detached": // COSName.ADBE_PKCS7_DETACHED
                                result.put(sig.getName(), verifyPKCS7(buf, contents, sig));

                                //TODO check certificate chain, revocation lists, timestamp...
                                break;
                            case "adbe.pkcs7.sha1": // COSName.ADBE_PKCS7_SHA1
                            {
                                // example: PDFBOX-1452.pdf
                                COSString certString = (COSString) sigDict.getDictionaryObject(
                                        COSName.CONTENTS);
                                byte[] certData = certString.getBytes();
                                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                                ByteArrayInputStream certStream = new ByteArrayInputStream(certData);
                                Collection<? extends Certificate> certs = factory.generateCertificates(certStream);
                                System.out.println("certs=" + certs);
                                byte[] hash = MessageDigest.getInstance("SHA1").digest(buf);
                                result.put(sig.getName(), verifyPKCS7(hash, contents, sig));

                                //TODO check certificate chain, revocation lists, timestamp...
                                break;
                            }
                            case "adbe.x509.rsa_sha1": // COSName.ADBE_PKCS7_SHA1
                            {
                                // example: PDFBOX-2693.pdf
                                COSString certString = (COSString) sigDict.getDictionaryObject(
                                        COSName.getPDFName("Cert"));
                                byte[] certData = certString.getBytes();
                                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                                ByteArrayInputStream certStream = new ByteArrayInputStream(certData);
                                Collection<? extends Certificate> certs = factory.generateCertificates(certStream);
                                System.out.println("certs=" + certs);

                                //TODO verify signature
                                throw new IOException(subFilter + " verification not supported");
                                //break;
                            }
                            default:
                                throw new IOException("Unknown certificate type: " + subFilter);
                                //break;
                        }
                    }
                    else
                    {
                        throw new IOException("Missing subfilter for cert dictionary");
                    }
                }
            }
            catch (CMSException | OperatorCreationException ex)
            {
                throw new IOException(ex);
            }

        return result;
    }

    /**
     * Verify a PKCS7 signature.
     *
     * @param byteArray the byte sequence that has been signed
     * @param contents the /Contents field as a COSString
     * @param sig the PDF signature (the /V dictionary)
     * @throws CertificateException
     * @throws CMSException
     * @throws StoreException
     * @throws OperatorCreationException
     */
    private SignatureResult verifyPKCS7(byte[] byteArray, COSString contents, PDSignature sig)
            throws CMSException, CertificateException, StoreException, OperatorCreationException
    {
        // inspiration:
        // http://stackoverflow.com/a/26702631/535646
        // http://stackoverflow.com/a/9261365/535646
        CMSProcessable signedContent = new CMSProcessableByteArray(byteArray);
        CMSSignedData signedData = new CMSSignedData(signedContent, contents.getBytes());
        Store certificatesStore = signedData.getCertificates();
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        SignerInformation signerInformation = signers.iterator().next();
        Collection matches = certificatesStore.getMatches(signerInformation.getSID());
        X509CertificateHolder certificateHolder = (X509CertificateHolder) matches.iterator().next();
        X509Certificate certFromSignedData = new JcaX509CertificateConverter().getCertificate(certificateHolder);
        //System.out.println("certFromSignedData: " + certFromSignedData);
        certFromSignedData.checkValidity(sig.getSignDate().getTime());

        JcaSimpleSignerInfoVerifierBuilder verifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
        if (provider != null) {
            verifierBuilder.setProvider(provider);
        }

        boolean validated = false;
        try {
            validated = signerInformation.verify(verifierBuilder.build(certFromSignedData));

        } catch (CMSSignerDigestMismatchException e) {
            System.out.println("Signature failed to validate: ");
            e.printStackTrace();
        }

        return new SignatureResult(certFromSignedData, validated);
    }
}
