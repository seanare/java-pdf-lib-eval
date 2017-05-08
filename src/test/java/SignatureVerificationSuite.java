import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        PdfBoxBouncyCastleSignatureVerifierTest.class,
        PdfBoxBouncyCastleAliasedProviderSignatureVerifierTest.class,
        OpenPdfSignatureVerificationTest.class,
        IcePdfSignatureVerificationTest.class
})
@Ignore
public class SignatureVerificationSuite {
}
