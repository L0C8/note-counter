package note.counter;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
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

    public static final class JSONCipherGCM {
        private static final String CIPHER = "AES/GCM/NoPadding";
        private static final int IV_LEN = 12;               // 96-bit nonce as recommended for GCM
        private static final int TAG_BITS = 128;            // 16-byte tag
        private static final int KEY_LEN_BITS = 256;        // 256-bit AES key
        private static final SecureRandom RNG = new SecureRandom();

        public static void encryptFile(Path inPath, Path outPath, byte[] key, byte[] aad) throws Exception {
            byte[] plaintext = Files.readAllBytes(inPath);
            String b64 = encryptToBase64(plaintext, key, aad);
            Files.write(outPath, b64.getBytes(StandardCharsets.UTF_8));
        }

        public static void decryptFile(Path inPath, Path outPath, byte[] key, byte[] aad) throws Exception {
            byte[] b64 = Files.readAllBytes(inPath);
            byte[] plain = decryptFromBase64(new String(b64, StandardCharsets.UTF_8), key, aad);
            Files.write(outPath, plain);
        }

        public static String encryptToBase64(byte[] data, byte[] key, byte[] aad) throws Exception {
            byte[] iv = new byte[IV_LEN];
            RNG.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) cipher.updateAAD(aad);

            byte[] ct = cipher.doFinal(data);

            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return Base64.getEncoder().encodeToString(out);
        }

        public static byte[] decryptFromBase64(String b64IvCt, byte[] key, byte[] aad) throws Exception {
            byte[] ivCt = Base64.getDecoder().decode(b64IvCt);
            if (ivCt.length < IV_LEN + 16) { 
                throw new IllegalArgumentException("Ciphertext too short");
            }
            byte[] iv = new byte[IV_LEN];
            byte[] ct = new byte[ivCt.length - IV_LEN];
            System.arraycopy(ivCt, 0, iv, 0, IV_LEN);
            System.arraycopy(ivCt, IV_LEN, ct, 0, ct.length);

            Cipher cipher = Cipher.getInstance(CIPHER);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) cipher.updateAAD(aad);

            return cipher.doFinal(ct);
        }

        private static final int SALT_LEN = 16;
        private static final int PBKDF2_ITERS = 200_000;

        private static byte[] deriveKey(char[] password, byte[] salt) throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERS, KEY_LEN_BITS);
            return skf.generateSecret(spec).getEncoded();
        }

        public static void encryptFileWithPassword(Path inPath, Path outPath, String password, byte[] aad) throws Exception {
            byte[] data = Files.readAllBytes(inPath);
            String b64 = encryptToBase64WithPassword(data, password, aad);
            Files.write(outPath, b64.getBytes(StandardCharsets.UTF_8));
        }

        public static void decryptFileWithPassword(Path inPath, Path outPath, String password, byte[] aad) throws Exception {
            byte[] b64 = Files.readAllBytes(inPath);
            byte[] plain = decryptFromBase64WithPassword(new String(b64, StandardCharsets.UTF_8), password, aad);
            Files.write(outPath, plain);
        }

        public static String encryptToBase64WithPassword(byte[] data, String password, byte[] aad) throws Exception {
            byte[] salt = new byte[SALT_LEN];
            RNG.nextBytes(salt);
            byte[] key = deriveKey(password.toCharArray(), salt);

            String b64Payload = encryptToBase64(data, key, aad);
            byte[] payload = Base64.getDecoder().decode(b64Payload);

            byte[] out = new byte[salt.length + payload.length];
            System.arraycopy(salt, 0, out, 0, salt.length);
            System.arraycopy(payload, 0, out, salt.length, payload.length);
            return Base64.getEncoder().encodeToString(out);
        }

        public static byte[] decryptFromBase64WithPassword(String b64SaltIvCt, String password, byte[] aad) throws Exception {
            byte[] saltIvCt = Base64.getDecoder().decode(b64SaltIvCt);
            if (saltIvCt.length < SALT_LEN + IV_LEN + 16) {
                throw new IllegalArgumentException("Ciphertext too short");
            }
            byte[] salt = new byte[SALT_LEN];
            byte[] ivCt = new byte[saltIvCt.length - SALT_LEN];
            System.arraycopy(saltIvCt, 0, salt, 0, SALT_LEN);
            System.arraycopy(saltIvCt, SALT_LEN, ivCt, 0, ivCt.length);
            byte[] key = deriveKey(password.toCharArray(), salt);
            String b64Payload = Base64.getEncoder().encodeToString(ivCt);
            return decryptFromBase64(b64Payload, key, aad);
        }
    }
}