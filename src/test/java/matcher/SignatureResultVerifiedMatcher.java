package matcher;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import signature.SignatureResult;

public class SignatureResultVerifiedMatcher extends TypeSafeMatcher<SignatureResult>
{
    private final boolean expectedVerificationResult;
    private final String partDescription;

    @Override
    public void describeTo(Description description)
    {
        description.appendValue(partDescription);
    }

    @Override
    protected boolean matchesSafely(SignatureResult item)
    {
        return item.isVerified() == expectedVerificationResult;
    }

    public static SignatureResultVerifiedMatcher verified()
    {
        return new SignatureResultVerifiedMatcher(true);
    }

    public static SignatureResultVerifiedMatcher failedToVerify()
    {
        return new SignatureResultVerifiedMatcher(false);
    }

    private SignatureResultVerifiedMatcher(boolean verificationSuccessful)
    {
        this.expectedVerificationResult = verificationSuccessful;
        if (verificationSuccessful) {
            partDescription = "passed verification";
        } else {
            partDescription = "failed verification";
        }
    }
}

