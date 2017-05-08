# pdf-verify-sign-nitro
The purpose of this project is to demonstrate an issue verifying adbe.pkcs7.detached 
digital signatures added by Nitro Pro 11 using the typical [PDFBox](pdfbox.apache.org)
and [Bouncy Castle](https://www.bouncycastle.org/) approach (for example in the PDFBox
[ShowSignature](https://svn.apache.org/viewvc/pdfbox/trunk/examples/src/main/java/org/apache/pdfbox/examples/signature/ShowSignature.java?revision=1792241&view=co) example).
As a result several unit tests are not passing by design.

The Nitro Pro 11 fixtures in this project are validated by Adobe Reader DC.

Assuming you have Java 8 installed, you can reproduce the issue thus:
```
./gradlew test --tests PdfBoxBouncyCastleSignatureVerifierTest
```
For the Nitro 11 Pro signed fixtures, this results in the following error:
```
java.security.NoSuchAlgorithmException: SHA1WITHRSA MessageDigest not available
```

Adding an alias from SHA1WITHRSA (as a Digest Algorithm) to SHA1 as per [this question](https://stackoverflow.com/questions/38740206/bouncycastle-set-custom-alias-to-algorithm):

```java
BouncyCastleProvider provider = new BouncyCastleProvider();
provider.addAlgorithm("Alg.Alias.MessageDigest.SHA1WITHRSA", "SHA-1");
provider.addAlgorithm("Alg.Alias.MessageDigest.1.2.840.113549.1.1.5", "SHA-1");
```

suppresses the exception, but the signatures fail to verify, as per this unit test:
```
./gradlew test --tests PdfBoxBouncyCastleAliasedProviderSignatureVerifierTest
```

mkl implemented a [validateSignaturesImproved()](https://github.com/mkl-public/testarea-pdfbox2/blob/master/src/test/java/mkl/testarea/pdfbox2/sign/ValidateSignature.java#L198) PDFBox and Bouncy Castle based PKCS#7 validation in response to
[this StackOverflow question](http://stackoverflow.com/a/41174166).  It has some slight differences with respect to the treatment of adbe.pkcs7.detached signatures to the PDFBox example and outputs additional diagnostic information,
as seen in this unit test:
```
./gradlew test --tests PdfBoxMklValidateSignatureTest
```