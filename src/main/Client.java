package main;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.SecretKey;

public class Client extends Thread {
	
	private static final int BITS_CLAVE_AES = 256;

	public static void main(String[] args) {
		try {
			

			System.out.println("Creando socket cliente");
			// Crear un nuevo socket cliente
			Socket clientSocket = new Socket();

			System.out.println("Estableciendo la conexión");
			// Establecer la dirección y el puerto al que se conectará el socket cliente
			InetSocketAddress addr = new InetSocketAddress("localhost", 5555);
			// Conectar el socket cliente a la dirección y puerto especificados
			clientSocket.connect(addr);
			// Crear un lector de entrada para recibir datos del servidor
			BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			// Obtener el flujo de salida del socket cliente para enviar datos al servidor
			OutputStream os = clientSocket.getOutputStream();
			// Crear un escritor de salida para enviar datos al servidor
			PrintWriter out = new PrintWriter(os, true);


			// Mensaje para generar claves RSA y recibir luego la clave publica RSA.
			System.out.println("Enviar petición al servidor para generar claves RSA.");
			out.println("Generar clave RSA.");

			
			// Recibir clave pública RSA del servidor
			System.out.println("Recibiendo clave publica RSA.");
			String publica = in.readLine();
			System.out.println("Clave publica recibida: " + publica);
			
			// Convertir la clave en objeto PublicKey
            //PublicKey clavePublicaRSAServidor = Cifrado.bytesAPublicKey(publica.getBytes());
			System.out.println("Convirtiendo clave publica en PublicKey");
			PublicKey clavePublicaRSAServidor = Cifrado.stringToPublicKey(publica);
			System.out.println("Clave publica convertida en objeto PublicKey");
            
			
            // Enviar confirmación al servidor después de recibir la clave pública RSA
            System.out.println("Enviando confirmacion al servidor de que se ha recibido la clave RSA.");
            out.println("Clave RSA recibida");
            out.flush();
            
            
            // Generar clave AES para cifrar mensajes
            System.out.println("Generando clave AES para cifrar mesajes.");
            SecretKey claveAES = Cifrado.generarClaveAES(BITS_CLAVE_AES);
            System.out.println("Clave AES generada correctamente."); 
            Cifrado.ImprimirClave("Clave AES sin encriptar: ", claveAES.getEncoded());
           

            // Cifrar clave AES con clave pública RSA del servidor
            System.out.println("Cifrando clave AES con clave pública RSA del servidor.");
            //byte[] claveAESCifrada = cifrarAESconRSA(clavePublicaRSAServidor, claveAES);
            byte[] claveAESCifrada  = EncriptacionRSA.encryptAESWithRSA(clavePublicaRSAServidor, claveAES);
            System.out.println("Clave AES cifrada correctamente con clave pública RSA.");
            Cifrado.ImprimirClave("Clave AES encriptada con RSA: ", claveAESCifrada);
            

            // Enviar clave AES cifrada al servidor
            System.out.println("Enviando clave AES cifrada con RSA al servidor...");
            // Enviar la longitud de la clave cifrada
            out.println(claveAESCifrada.length);
            out.flush();

            // Enviar la clave cifrada
            os.write(claveAESCifrada);
            out.flush();

            // Mensaje de confirmación
            System.out.println("Clave AES cifrada enviada al servidor.");

            // Esperar la confirmación del servidor
            String confirmacion = in.readLine();
            System.out.println("Confirmación del servidor: " + confirmacion);

            // Verificar si la confirmación es recibida correctamente
            if (confirmacion.equals("Clave RSA recibida")) {
                System.out.println("Clave recibida correctamente");
            }

            // Cifrar y enviar un mensaje al servidor
            String mensajeCifrado = EncriptacionAES.cifrarMensajeAES(claveAES, "Este es un mensaje cifrado con AES desde el cliente");
            System.out.println("Enviando mensaje cifrado al servidor...");
            out.println(mensajeCifrado);
            out.flush();
            System.out.println("Mensaje cifrado con AES enviado al servidor.");
            
            
            // Recibir mensaje cifrado de servidor
            System.out.println("Esperando respuesta del servidor.");
            String mensajeCifradoServidor = in.readLine();
            System.out.println("Mensaje cifrado recibido del servidor: " + mensajeCifradoServidor);

            // Decodificar el mensaje cifrado desde Base64
            byte[] mensajeCifradoBytes = Base64.getDecoder().decode(mensajeCifradoServidor);

            // Descifrar el mensaje
            String mensajeDescifradoServidor = EncriptacionAES.descifrarMensajeAES2(claveAES, mensajeCifradoBytes);

            // Mostrar mensaje del servidor
            System.out.println("Mensaje descifrado del servidor: " + mensajeDescifradoServidor);

            
            // Cerrar socket cliente
            System.out.println("Cerrando el socket cliente");
            clientSocket.close();
            System.out.println("Terminado");

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	
}
