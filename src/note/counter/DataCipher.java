package note.counter;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class DataCipher {

    public static final class AESCipher {
        private static final String CIPHER = "AES/CBC/PKCS5Padding"; 
        private static final SecureRandom RNG = new SecureRandom();

        // key must be 16/24/32 bytes for AES-128/192/256
        public static String encrypt(String plaintext, byte[] key) throws Exception {
            byte[] iv = new byte[16];
            RNG.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

            byte[] paddedCipher = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] ivPlusCt = new byte[iv.length + paddedCipher.length];
            System.arraycopy(iv, 0, ivPlusCt, 0, iv.length);
            System.arraycopy(paddedCipher, 0, ivPlusCt, iv.length, paddedCipher.length);

            return Base64.getEncoder().encodeToString(ivPlusCt);
        }

        public static String decrypt(String b64IvPlusCiphertext, byte[] key) throws Exception {
            byte[] ivPlusCt = Base64.getDecoder().decode(b64IvPlusCiphertext);
            if (ivPlusCt.length < 17) {
                throw new IllegalArgumentException("Invalid ciphertext");
            }
            byte[] iv = new byte[16];
            byte[] ct = new byte[ivPlusCt.length - 16];
            System.arraycopy(ivPlusCt, 0, iv, 0, 16);
            System.arraycopy(ivPlusCt, 16, ct, 0, ct.length);

            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            byte[] pt = cipher.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        }
    }

    public static final class AESCipherPass {
        private static final String CIPHER = "AES/ECB/PKCS5Padding";

        private static byte[] setKey(String password) throws Exception {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] digest = sha1.digest(password.getBytes(StandardCharsets.UTF_8));
            // first 16 bytes -> AES-128 key
            byte[] key16 = new byte[16];
            System.arraycopy(digest, 0, key16, 0, 16);
            return key16;
        }

        public static String encrypt(String plaintext, String password) throws Exception {
            byte[] key = setKey(password);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ct);
        }

        public static String decrypt(String b64Ciphertext, String password) {
            try {
                byte[] key = setKey(password);
                byte[] ct = Base64.getDecoder().decode(b64Ciphertext);
                Cipher cipher = Cipher.getInstance(CIPHER);
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
                byte[] pt = cipher.doFinal(ct);
                return new String(pt, StandardCharsets.UTF_8);
            } catch (Exception e) {
                return "Error decrypting: " + e.getMessage();
            }
        }
    }

}