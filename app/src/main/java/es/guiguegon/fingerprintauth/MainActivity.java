package es.guiguegon.fingerprintauth;

import android.app.KeyguardManager;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;
import java.security.KeyStore;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    public final String TAG = this.getClass()
            .getSimpleName();
    public final static String KEY_NAME = "key_name_unique";
    public final static String SECRET_PASSWORD = "secret_password";
    private FingerprintManager mFingerprintManager;
    private KeyguardManager keyguardManager;
    private KeyGenerator keyGenerator;
    private KeyStore mKeyStore;
    private Cipher mCipher;
    private CancellationSignal mCancellationSignal;
    private FingerprintManager.CryptoObject cryptoObject;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(this::onFingerAuth);
        keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        initKeyStore();
        initKeyGenerator();
        initCypher();
    }

    private void initKeyStore() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                mKeyStore = KeyStore.getInstance("AndroidKeyStore");
                mKeyStore.load(null, null);
            } catch (Exception e) {
                throw new RuntimeException("Failed to get an instance of KeyStore", e);
            }
        }
    }

    private void initCypher() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES
                        + "/"
                        + KeyProperties.BLOCK_MODE_CBC
                        + "/"
                        + KeyProperties.ENCRYPTION_PADDING_PKCS7);
                // init the cipher
                SecretKey secretKey = (SecretKey) mKeyStore.getKey(KEY_NAME, null);
                mCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void initKeyGenerator() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                // Get an instance to the key generator using AES
                keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                        "AndroidKeyStore");
                int purpose = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;
                // Init the generator
                keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME, purpose).setBlockModes(
                        KeyProperties.BLOCK_MODE_CBC)
                        // key allowed only when user is authenticated
                        .setUserAuthenticationRequired(true)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .build());
                // generate the key
                keyGenerator.generateKey();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void onFingerAuth(View view) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mFingerprintManager =
                    (FingerprintManager) getSystemService(Context.FINGERPRINT_SERVICE);
            mCancellationSignal = new CancellationSignal();
            // The line below prevents the false positive inspection from Android Studio
            // noinspection ResourceType
            mFingerprintManager.authenticate(new FingerprintManager.CryptoObject(mCipher),
                    mCancellationSignal, 0 /* flags */,
                    new FingerprintManager.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationError(int errorCode, CharSequence errString) {
                            super.onAuthenticationError(errorCode, errString);
                            Log.w(TAG, "onAuthenticationError");
                        }

                        @Override
                        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                            super.onAuthenticationHelp(helpCode, helpString);
                            Log.w(TAG, "onAuthenticationHelp");
                        }

                        @Override
                        public void onAuthenticationSucceeded(
                                FingerprintManager.AuthenticationResult result) {
                            super.onAuthenticationSucceeded(result);
                            Log.w(TAG, "onAuthenticationSucceeded");
                            crypto();
                        }

                        @Override
                        public void onAuthenticationFailed() {
                            super.onAuthenticationFailed();
                            Log.w(TAG, "onAuthenticationFailed");
                        }
                    }, null);
        }
    }

    private void crypto() {
        tryEncrypt();
    }

    /**
     * Tries to encrypt some data with the generated key in {@link #createKey} which is
     * only works if the user has just authenticated via fingerprint.
     */
    private void tryEncrypt() {
        try {
            byte[] encrypted = mCipher.doFinal(SECRET_PASSWORD.getBytes());
            String encryptedString = Base64.encodeToString(encrypted, 0 /* flags */);
            Toast.makeText(this, "secret " + encryptedString, Toast.LENGTH_LONG).show();
            Log.i(TAG, "secret " + encryptedString);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            Toast.makeText(this, "Failed to encrypt the data with the generated key. "
                    + "Retry the purchase", Toast.LENGTH_LONG).show();
            Log.e(TAG, "Failed to encrypt the data with the generated key." + e.getMessage());
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
