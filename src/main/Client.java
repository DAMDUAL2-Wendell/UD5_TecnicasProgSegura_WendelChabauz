package main;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Client extends Thread {
	
	private static final int BITS_CLAVE_AES = 256;

	public static void main(String[] args) {
		try {
			// Mensaje que será cifrado usando cifrado asimétrico y enviado al servidor
			String mensaje = "Mensaje de prueba del cifrado asimétrico";
			System.out.println("Creando socket cliente");
			Socket clientSocket = new Socket();
			System.out.println("Estableciendo la conexión");
			InetSocketAddress addr = new InetSocketAddress("localhost", 5555);
			clientSocket.connect(addr);
			DataInputStream is = new DataInputStream(clientSocket.getInputStream());
			DataOutputStream os = new DataOutputStream(clientSocket.getOutputStream());;

			// Mensaje para generar claves RSA y recibir luego la clave publica RSA.
			System.out.println("Enviar petición al servidor para generar claves RSA.");
			os.write("Generar clave RSA.".getBytes());

			System.out.println("Recibiendo clave publica RSA.");
			// Recibir clave pública RSA del servidor
			byte[] publica = Cifrado.leerDatosDataInputStream(is,is.readInt());
            PublicKey clavePublicaRSAServidor = Cifrado.bytesAPublicKey(publica);
            
            System.out.println("Enviando confirmacion al servidor de que se ha recibido la clave RSA.");
            // Enviar confirmación al servidor después de recibir la clave pública RSA
            os.write("Clave RSA recibida".getBytes());

            System.out.println("Generando clave AES para cifrar mesajes.");
            // Generar clave AES para cifrar mensajes
            SecretKey claveAES = generarClaveAES();

            System.out.println("Cifrando clave AES con clave pública RSA del servidor.");
            // Cifrar clave AES con clave pública RSA del servidor
            byte[] claveAESCifrada = cifrarAESconRSA(clavePublicaRSAServidor, claveAES);

            System.out.println("Enviando clave AES cifrada con RSA al servidor...");
            // Enviar clave AES cifrada al servidor
            enviarClaveAESCifradaAlServidor(os, claveAESCifrada);
            
   			
			System.out.println("Cerrando el socket cliente");

			clientSocket.close();

			System.out.println("Terminado");

		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	

	private static PublicKey recibirClavePublicaRSA(DataInputStream entrada) {
	    try {
	        // Recibir clave pública RSA del servidor
	        byte[] clavePublicaEncoded = new byte[entrada.readInt()];
	        entrada.readFully(clavePublicaEncoded);
	        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(clavePublicaEncoded));
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	private static SecretKey generarClaveAES() {
	    try {
	        // Generar clave AES
	        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	        keyGenerator.init(BITS_CLAVE_AES);
	        return keyGenerator.generateKey();
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	private static byte[] cifrarAESconRSA(PublicKey clavePublicaRSA, SecretKey claveAES) {
	    try {
	        // Cifrar clave AES con clave pública RSA del servidor
	        Cipher cifradorRSA = Cipher.getInstance("RSA");
	        cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePublicaRSA);
	        return cifradorRSA.doFinal(claveAES.getEncoded());
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	private static void enviarClaveAESCifradaAlServidor(DataOutputStream salida, byte[] claveAESCifrada) {
	    try {
	        // Enviar clave AES cifrada al servidor
	        salida.writeInt(claveAESCifrada.length);
	        salida.write(claveAESCifrada);
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	}
	
	
}
