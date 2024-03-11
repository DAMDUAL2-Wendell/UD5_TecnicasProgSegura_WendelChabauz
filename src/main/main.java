package main;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class main {

	public static void main(String[] args) {
		try {
			// Cantidad de bits para generar las claves
			int bitsClaveRSA = 2048;
			int bitsClaveAES = 256;

			// Inicialización de los objetos Cipher para cifrado RSA y AES
			Cipher rsaCipher = Cipher.getInstance("RSA");
			Cipher aesCipher = Cipher.getInstance("AES");

			// Mensaje que será cifrado usando cifrado asimétrico
			String mensaje = "Mensaje de prueba del cifrado asimétrico";

			// Generar par de claves RSA
			KeyPair keypairRSA = GenerarClavesRSA(bitsClaveRSA);

			// Imprimir claves
			ImprimirClavesRSA(keypairRSA);

			// Generar clave AES para cifrado simétrico de los datos
			byte[] secretAesKey = GenerarClaveAES(bitsClaveAES);
			ImprimirClave("Clave AES: ", secretAesKey);

			// Cifrar clave AES con clave pública RSA
			byte[] encryptedAESSecretKey = CifrarAESconRSA(rsaCipher, keypairRSA, secretAesKey);
			ImprimirClave("Clave AES encriptada: ", encryptedAESSecretKey);

			// Descifrar clave AES con clave privada RSA
			byte[] decryptedAESSecretKey = DescifrarAESconRSA(rsaCipher, keypairRSA, encryptedAESSecretKey);

			// Imprimir la clave AES descifrada para verificar que coincide con la original
			ImprimirClave("Clave AES descifrada: ", decryptedAESSecretKey);

			// Comparación de claves AES original y descifrada
			boolean keysMatch = java.util.Arrays.equals(secretAesKey, decryptedAESSecretKey);
			System.out.println("Las claves AES coinciden: " + (keysMatch ? "Si" : "No"));

			// Imprimir mensaje original sin encriptar
			System.out.println("Mensaje a encriptar: " + mensaje);
			
			// Cifrar mensaje con clave AES
			byte[] encryptedMessageAES = CifrarMensajeConAES(aesCipher, decryptedAESSecretKey, mensaje);
			ImprimirClave("Mensaje cifrado: ", encryptedMessageAES);

			// Descifrar mensaje con clave AES
			byte[] decryptedMessageAES = DesCifrarMensajeConAES(aesCipher, decryptedAESSecretKey, encryptedMessageAES);
			System.out.println("Mensaje descifrado: " + new String(decryptedMessageAES));

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static KeyPair GenerarClavesRSA(int longitudBits) {
		// Generar claves RSA
		KeyPairGenerator keygenRSA;
		KeyPair keypairRSA = null;
		try {
			keygenRSA = KeyPairGenerator.getInstance("RSA");
			keygenRSA.initialize(longitudBits);
			keypairRSA = keygenRSA.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error al generar claves RSA." + e.getMessage());
		}

		return keypairRSA;
	}

	public static void ImprimirClavesRSA(KeyPair keypairRSA) {
		// Obtener claves pública y privada RSA
		PublicKey publicKey = keypairRSA.getPublic();
		PrivateKey privateKey = keypairRSA.getPrivate();

		// Imprimir claves pública y privada en formato Base64
		System.out.println("Clave pública RSA: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
		System.out.println("Clave privada RSA: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
	}

	// Generar clave AES para cifrado simétrico de los datos
	public static byte[] GenerarClaveAES(int longitudBits) {
		KeyGenerator keygenAES;
		byte[] secretKey = null;
		try {
			keygenAES = KeyGenerator.getInstance("AES");
			keygenAES.init(longitudBits);
			secretKey = keygenAES.generateKey().getEncoded();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error al generar clave AES." + e.getMessage());
		}
		return secretKey;
	}

	// Cifrar clave AES con clave pública RSA
	public static byte[] CifrarAESconRSA(Cipher rsaCipher, KeyPair keypairRSA, byte[] secretAesKey) {
		byte[] encryptedSecretKey = null;
		try {
			rsaCipher.init(Cipher.ENCRYPT_MODE, keypairRSA.getPublic());
			encryptedSecretKey = rsaCipher.doFinal(secretAesKey);
		} catch (Exception e) {
			System.out.println("Error al cifrar clave AES con clave publica RSA." + e.getMessage());
		}
		return encryptedSecretKey;
	}

	// Descifrar clave AES con clave privada RSA
	public static byte[] DescifrarAESconRSA(Cipher rsaCipher, KeyPair keypairRSA, byte[] encryptedAESSecretKey) {
		byte[] decryptedSecretKey = null;
		try {
			rsaCipher.init(Cipher.DECRYPT_MODE, keypairRSA.getPrivate());
			decryptedSecretKey = rsaCipher.doFinal(encryptedAESSecretKey);
		} catch (Exception e) {
			System.out.println("Error al descifrar clave AES con clave privada RSA." + e.getMessage());
		}
		return decryptedSecretKey;
	}

	// Imprimir la clave AES descifrada para verificar que coincide con la original
	public static void ImprimirClave(String msg, byte[] key) {
		System.out.println(msg + Base64.getEncoder().encodeToString(key));
	}

	// Cifrar mensaje con AES
	public static byte[] CifrarMensajeConAES(Cipher aesCipher, byte[] decryptedSecretKey, String mensaje) {
		byte[] encryptedMessage = null;
		try {
			aesCipher.init(Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(decryptedSecretKey, "AES"));
			encryptedMessage = aesCipher.doFinal(mensaje.getBytes());
		} catch (Exception e) {
			System.out.println("Error al cifrar mensaje con clave AES." + e.getMessage());
		}
		return encryptedMessage;
	}

	// Descifrar mensaje con AES
	public static byte[] DesCifrarMensajeConAES(Cipher aesCipher, byte[] decryptedSecretKey, byte[] encryptedMessage) {
		byte[] decryptedMessage = null;
		try {
			aesCipher.init(Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(decryptedSecretKey, "AES"));
            decryptedMessage = aesCipher.doFinal(encryptedMessage);
		} catch (Exception e) {
			System.out.println("Error al cifrar mensaje con clave AES." + e.getMessage());
		}
		return decryptedMessage;
	}

}
