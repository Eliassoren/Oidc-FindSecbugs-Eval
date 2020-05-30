package oidc.nimbus.badpractice;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import oidc.otherexamples.AuthResource;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class InsecureDeleteSecret {

    static SecureRandom secureRandomGenerator;
    static AuthResource.Config config;
    static {

        try {
            secureRandomGenerator = SecureRandom.getInstance("SHA1PRNG", "SUN");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }



    // Expect to trigger UNSAFE_DELETE_SECRET_AUTH
    public static void secretPossiblyNotErased() {
        Secret secret = new Secret("foo");
        if (randomCase()) {
            return; // Secret is now in cache and not deleted yet
        }
        else if(StringUtils.isBlank(secret.getValue())) { // Usage of variable. Otherwise this triggers variable not used (Dead local storage)
            return;
        }
        secret.erase();
    }

    // Expect to trigger UNSAFE_DELETE_SECRET_AUTH_EXCEPTION_PATH
    public static void secretPossiblyNotErasedBecauseOfCheckedException() {
        try {
            Secret secret = new Secret("foo");
            randomlyThrowCheckedException();
            secret.erase();
        } catch (Exception e){
            // Do stuff
        }
    }

    // Does not trigger normal test, but triggers UNSAFE_DELETE_SECRET_AUTH_EXCEPTION_PATH
    public static void secretPossiblyNotErasedExceptionNaiveNoTry() {
        Secret secret = new Secret("foo");
        if (randomCase()) {
            secret.erase();
            // Other operations
            return;
        } else if (StringUtils.isBlank(secret.getValue())) { // Usage of variable
            secret.erase();
            // Other operations
            return;
        }
        secret.erase();
    }

    // Expect UNSAFE_DELETE_SECRET_AUTH_EXCEPTION_PATH
    public static void secretPossiblyNotErasedBecauseOfExceptionAndConditional() {
        Secret secret = null;
        try {
            secret = new Secret("foo");
            randomlyThrowException();
        } catch (Exception e) {
            //
        }
        finally {
            if(secret != null) {
                secret.erase();
            }
        }
    }

    public static void OK_secretPossiblyNotErased() {
        Secret secret = new Secret("foo");
        try {
            if (randomCase()) {
                secret.erase();
                // Other operations
                return;
            } else if (StringUtils.isBlank(secret.getValue())) { // Usage of variable
                secret.erase();
                // Other operations
                return;
            }
        } finally {
            secret.erase();
        }

    }


    public static void OK_secretPossiblyNotErasedBecauseOfCheckedException_1() {
        Secret secret = new Secret("foo");
        try {
            randomlyThrowCheckedException();
            //throw new NullPointerException("EE");
        } catch (Exception e) {
            // log error
        } finally {
            secret.erase();
        }
    }




    public static void OK_secretPossiblyNotErasedBecauseOfException_1() {
        Secret secret = new Secret("foo");
        try {
            randomlyThrowException();
        } catch (Exception e) {
            // log errors
        } finally {
            secret.erase();
        }
    }




    private static void randomlyThrowException() {
        throw new RuntimeException();
    }

    private static void randomlyThrowCheckedException() throws Exception {
        int a = 2*5;
    }

    public static void notStrongEnoughtStatusCodeChecking() {
        int statusCode = createStatusCode();
        if (statusCode == 401 || statusCode == 402) {
            throw new RuntimeException();
        }

    }

    public static boolean randomCase() {
        return secureRandomGenerator.nextInt() > 0.5;
    }


    private static int createStatusCode() {
        return (405)*secureRandomGenerator.nextInt();
    }
}
