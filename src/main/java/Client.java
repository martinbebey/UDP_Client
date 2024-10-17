package main.java;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
//import java.io.InterruptedIOException;
//import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
//import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
//import java.security.interfaces.ECPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Cipher;
//import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.plaf.basic.BasicSplitPaneUI.KeyboardUpLeftHandler;

/**
 * This is the client program
 */
public class Client 
{
	private static DatagramSocket socket;
	private static InetAddress address;
	private static byte[] buf;
	private static long averageEncryptionTime;
	private static long averageDecryptionTime;
	private static long averageResponseTime;
	private static long averagePacketSentSize;
	private static long averagePacketReceivedSize;
	private static long encryptionCount = 0;
	private static long decryptionCount = 0;
	private static long numberOfMessagesSent = 0;
	
	private static String encryptedMessage = "message";
	private static byte[] initVector;
	private static SecretKey key = null;
	private static String cipherBlockChainKey;// = "masterkey694";
	//private final static int KEY_SIZE = 128;
	private final static int DATA_LENGTH = 128;
	private static int privateValue; //a and b
	private static int symmetricKey;
	private static Cipher encryptionCipher = null;
	private static byte[] HMAC_KEY;// = { 0x60, 0x51, 0x41, 0x30, 0x20, 0x11, 0x04, 0x70 }; //pre-shared between clients
//	private AuthenticatorNode authenticator = null;
	private static PrivateKey privateKeyDS = null; //private/public keys used to sign/authenticate with DSA
	private static KeyPairGenerator keyPairGen = null; //key pair generator object
	private static KeyPair pair = null;
	private static Signature digitalSignature = null;
	private static boolean logingIn;
	private static boolean buyingStock;
	private static boolean sellingStock = false;
	private static File stocksDB = new File("C:\\Users\\betoc\\eclipse-workspace\\UdpBroker\\src\\main\\java\\stocks.txt"); //("C:\\Apps\\Eclipse_Neon\\Workspace\\Networking\\src\\stocks.txt");
	public static PublicKey publicKeyDS = null;
	public static 	byte[] hmacSignature;
	public static byte[] messageDigitalSignature = null;
	public static String clientName = "User";
	public static boolean newMessage = false;
	public static int P; //publicly available 
	public static int G;
	public static int publicValue;

	public static void main(String[] args) throws Exception 
	{
		Client client = new Client();
		boolean stop = false;
		String command = "", response = "";
		BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
		
		//generated at random
		P = ThreadLocalRandom.current().nextInt(3,34);
		G = ThreadLocalRandom.current().nextInt(2,9);
		
		//send p and g (used for DH key exchange)
		client.sendMessage(Integer.toString(P));
		client.sendMessage(Integer.toString(G));
		
//		System.out.println("P value: " + P);
//		System.out.println("G value: " + G);
		
		//generate different keys for the different algorithms
		for(int i = 0; i < 3; ++i)
		{
			setPrivateValue();
			setPublicValue();
			
			//exchange public values
//			System.out.println("sending public value to broker: " + publicValue);
			publicValue = Integer.parseInt(client.sendMessage(Integer.toString(publicValue)));
//			System.out.println("public value received from broker: " + publicValue);
			
			setSymmetricKey();
			
			if(i == 0) {
				setHMACKey();
			}
			else if(i == 1) {
				setCipherBlockKey();
			}
			else {
				GenerateAESKey();
			}	
		}
		
		GenerateDigitalSignature();
		
		System.out.println("Please press: [1]Login [2]Stock Info [3]Buy [4]Sell \n");
		
		while(!stop) 
		{
			command = input.readLine();
			//print message from client to console
			System.out.println("\n" + clientName + " wrote: " + command + "\n");

			encryptedMessage = ThreeLayerEncryption(command);
			
			System.out.println("Cipher Block Chain Encryption: " + encryptedMessage);

			//digital signature - integrity, authenticity, non-repudiation
			digitalSignature.update(encryptedMessage.getBytes());
			messageDigitalSignature = digitalSignature.sign();
			System.out.println("Digital signature applied to encrypted message: " + messageDigitalSignature);

			//converting public key to byte            
			byte[] byte_pubkey = publicKeyDS.getEncoded();
//			System.out.println("\nBYTE KEY::: " + byte_pubkey);

			//converting byte to String 
			String str_publicKeyDS = Base64.getEncoder().encodeToString(byte_pubkey);
			String str_messageDS = Base64.getEncoder().encodeToString(messageDigitalSignature);
			String str_hmacSignature = Base64.getEncoder().encodeToString(hmacSignature);
			String initializationVector = Base64.getEncoder().encodeToString(encryptionCipher.getIV());
			System.out.println("Sending IV to broker: " + initializationVector);
			// String str_key = new String(byte_pubkey, Charset.);
//			System.out.println("\nSTRING KEY::" + str_key);

			
			//send and receives a packet
			response = sendMessage(encryptedMessage + "|" + clientName + "|" + str_hmacSignature + "|" + str_messageDS + "|" + str_publicKeyDS + "|" + initializationVector);
			
//			breakdown response
//			String encryptedResponse = response.split("|")[0];
//			String brokerName = response.split("|")[1];
//			byte[] brokerHMACSignature = response.split("|")[2].getBytes();
//			byte[] brokerDigitalSignature = response.split("|")[3].getBytes();
//			
//			KeyFactory factory = KeyFactory.getInstance("DSA", "BC");
//			PublicKey brokerPublicKeyDS = (ECPublicKey) factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(response.split("|")[4])));
//			
//			//process response
//			ProcessResponse(encryptedResponse, brokerName, brokerHMACSignature, brokerDigitalSignature, brokerPublicKeyDS);
			
			//breakdown response
			String encryptedResponse = response.split("\\|")[0];
			String senderName = response.split("\\|")[1];
			byte[] userHMACSignature = Base64.getDecoder().decode(response.split("\\|")[2].getBytes());
			byte[] userDigitalSignature = Base64.getDecoder().decode(response.split("\\|")[3].getBytes());
			System.out.println("received iv string: " + response.split("\\|")[5].trim());
			initVector = Base64.getDecoder().decode(response.split("\\|")[5].trim().getBytes());
//			System.out.println(clientName + " received encrypted message: " + encryptedResponse);
			System.out.println(clientName + " received HMAC signature: " + response.split("\\|")[2]);
			System.out.println(clientName + " received DS signature: " + response.split("\\|")[3]);
			
			KeyFactory factory = KeyFactory.getInstance("DSA");
			String keyString = response.split("\\|")[4].trim();
//			System.out.println("####################################################" + keyString);
			byte[] keyByte = Base64.getDecoder().decode(keyString.trim());
			PublicKey brokerPublicKeyDS = (PublicKey) factory.generatePublic(new X509EncodedKeySpec(keyByte));
			
			//process response
			ProcessResponse(encryptedResponse, senderName, userHMACSignature, userDigitalSignature, brokerPublicKeyDS);
		}

	}

	public Client() throws SocketException, UnknownHostException 
	{
		socket = new DatagramSocket();
		address = InetAddress.getByName("localhost");
	}

	/**
	 * Wraps a given string input from the user into a packet that is sent to the server.
	 * @param msg the message to be included in the packet to be sent to the server.
	 * @return the response from the server.
	 * @throws IOException
	 */
	public static String sendMessage(String msg) throws IOException 
	{
		buf = msg.getBytes();
//		int bufferLength = buf.length;
//		System.out.println("client length" + bufferLength);
		DatagramPacket packet = new DatagramPacket(buf, buf.length, address, 5000);
		System.out.println("Sending packet of size: " + packet.getLength());
		averagePacketSentSize += packet.getLength();
		System.out.println("Average size of packets sent: " + averagePacketSentSize);
		socket.send(packet);
		
		++numberOfMessagesSent;
		long startTime = System.nanoTime();
		
		buf = new byte[5000];
		packet = new DatagramPacket(buf, buf.length);
		socket.receive(packet);
		
		long stopTime = System.nanoTime();
		System.out.println("Time betwen message and response: " + (stopTime - startTime) + "ns");
		averageResponseTime += (stopTime - startTime) / numberOfMessagesSent;
		System.out.println("Average message response time over " + numberOfMessagesSent + " messages: " + averageResponseTime + "ns");
		
		//receiving server response
		String received = new String(packet.getData(), 0, packet.getLength());
		System.out.println("Receiving packet of size: " + packet.getLength());
		averagePacketReceivedSize += packet.getLength();
		System.out.println("Average size of packets received: " + averagePacketReceivedSize);
//		System.out.println("Received from Broker: " + received.split("\\|")[0]);
		return received;
	}

	public void close() 
	{
		socket.close();
	}
	
	private static void GenerateDigitalSignature() throws NoSuchAlgorithmException, InvalidKeyException
	{
		keyPairGen = KeyPairGenerator.getInstance("DSA"); //Creating KeyPair generator object
		keyPairGen.initialize(2048); //Initializing the key pair generator
		pair = keyPairGen.generateKeyPair();
		privateKeyDS = pair.getPrivate();
		publicKeyDS = pair.getPublic();
		digitalSignature = Signature.getInstance("SHA256withDSA"); //Creating a Signature object
		digitalSignature.initSign(privateKeyDS); //Initialize the signature
	}

	public static boolean Verify_Digital_Signature(byte[] input, byte[] signatureToVerify, PublicKey key) throws Exception
	{ 
		Signature signature = Signature.getInstance("SHA256withDSA"); 
		signature.initVerify(key); 
		signature.update(input); 
		return signature.verify(signatureToVerify); 
	} 

//	public void setAuthenticator(AuthenticatorNode auth)
//	{
//		this.authenticator = auth;
//	}

	/**
	 * Sets the value of P and G used to compute the public value.
	 * The public value will be used to exchange keys for Diffie-Hellman
	 * @param p
	 * @param g
	 */
	public void setPG(int p, int g) 
	{
		P = p;
		G = g;
	}

	public static void setPrivateValue() 
	{
		privateValue = ThreadLocalRandom.current().nextInt(2,257); //private value used in DH
	}

	public static void setCipherBlockKey()
	{
		cipherBlockChainKey = Integer.toString(symmetricKey);
	}

	public static void setHMACKey()
	{
		HMAC_KEY = ByteBuffer.allocate(8).putInt(symmetricKey).array();
	}

	public static void setPublicValue()
	{
		publicValue = calculateValue(G, privateValue, P); //public value used in DH
	}

	//	public int getPublicValue()
	//	{
	//		return publicValue;
	//	}

	public static void setSymmetricKey()
	{
		symmetricKey = calculateValue(publicValue, privateValue, P);//DH key exchange
//		System.out.println("sym key = " + symmetricKey);
	}

	//method to find the value of G ^ a mod P  (DH key exchange)
	private static  int calculateValue(int G, int power, int P)  
	{  
		int result = 0;

		if (power == 1)
		{  
			return G;  
		}  

		else
		{  
			result = ((int)Math.pow(G, power)) % P;  
			return result;  
		}  
	}

	/**
	 * Provides an HMAC signature to the encrypted message
	 * @param encryptedMessage the message to be signed
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private static void HMAC_Sign(String encryptedMessage) throws NoSuchAlgorithmException, InvalidKeyException
	{
		Mac mac = Mac.getInstance("HmacSHA256");
		KeySpec keySpec = new SecretKeySpec(HMAC_KEY, "HmacSHA256"); 
		mac.init((Key) keySpec);
		mac.update(encryptedMessage.getBytes());
		hmacSignature = mac.doFinal();
		System.out.println("HMAC signature applied to message: " + hmacSignature);

	}

	/**
	 * Checks the HMAC signature of the message received
	 * @param message
	 * @param hmacSignature
	 * @return true if the verification is successful, false otherwise 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static boolean isMessageAuthentic(String message, byte[] hmacSignature) throws NoSuchAlgorithmException, InvalidKeyException
	{
		Mac mac = Mac.getInstance("HmacSHA256");
		KeySpec keySpec = new SecretKeySpec(HMAC_KEY, "HmacSHA256"); 
		mac.init((Key) keySpec);
		mac.update(message.getBytes());

		if (Arrays.equals(mac.doFinal(), hmacSignature))
		{
			System.out.println("Message Integrity is verified :)");
			return true;
		}

		else
		{
			System.out.println("Message Integrity is compromised :(");
			return false;
		}
	}

	/**
	 * AES-GCM encryption
	 * @param message
	 * @return encrypted data as a string
	 * @throws Exception
	 */
	public static String Encrypt(String message) throws Exception
	{		
		//GenerateAESKey();
		String encryptedData = encrypt(message);

		System.out.println("Message AES-GCM encrypted by " + clientName + ": " + encryptedData);

		return encryptedData;
	}

	//AES-GCM encryption
	public static String encrypt(String data) throws Exception 
	{
		byte[] dataInBytes = data.getBytes();
		encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
		System.out.println("iv: " + encryptionCipher.getIV());
		System.out.println("key: " + key);
//		System.out.println("decrypted bs: " + decrypt(encode(encryptedBytes)));
		return encode(encryptedBytes);
	}

	/**
	 * Decrypts a given AES encrypted message
	 * @param encryptedData
	 * @return
	 * @throws Exception
	 */
	public static String decrypt(String encryptedData) throws Exception 
	{
		byte[] dataInBytes = decode(encryptedData);
		Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, initVector);
		decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
		byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
		return new String(decryptedBytes);
	}

	public static String CCMP_Encrypt(String plaintext, String key) throws Exception 
	{
		// Generate a 256-bit key from the given encryption key
		byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		keyBytes = sha.digest(keyBytes);
		keyBytes = Arrays.copyOf(keyBytes, 16);

		// Create a secret key specification from the key bytes
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

		// Create a cipher instance and initialize it with the secret key
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

		// Encrypt the plaintext
		byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

		// Encode the encrypted bytes to Base64 string
		//encode(encryptedBytes);
		return Base64.getEncoder().encodeToString(encryptedBytes);
	}

	public static String CCMP_Decrypt(String ciphertext, String key) throws Exception {
		// Generate a 256-bit key from the given decryption key
		byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		keyBytes = sha.digest(keyBytes);
		keyBytes = Arrays.copyOf(keyBytes, 16);

		// Create a secret key specification from the key bytes
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

		// Create a cipher instance and initialize it with the secret key
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

		// Decode the Base64 string to encrypted bytes
		byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);

		// Decrypt the ciphertext
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

		// Convert the decrypted bytes to plain text
		//encode(decryptedBytes);
		return new String(decryptedBytes, StandardCharsets.UTF_8);
	}

//	public String getMessage()
//	{
//		this.newMessage = false;
//		return encryptedMessage;
//	}
	
	/******************** below are different versions of the same method used to perform the decryptions in different orders ***************************/

	//GHC
//	public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
//	{
//		String decryptedData = "";
//		++decryptionCount;
//
//		System.out.println("Message received by " + clientName + ": " + message);
//
//		//verify digital signature
//		if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
//		{
//			System.out.println("Digital signature verified :)");
//			
//			long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//			long startTime = System.nanoTime();//start timer
//
//			decryptedData = decrypt(message);
//
//
//			if(isMessageAuthentic(decryptedData, hmacSignature))
//			{					
//				message = CCMP_Decrypt(decryptedData, cipherBlockChainKey);
//				System.out.println("Decrypted Cipher Block Chain: " + message);
//				long stopTime = System.nanoTime();// stop timer
//				long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//				long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//				System.out.println("Memory used during decryption: " + actualUsedMemory + " bytes");
//				System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
//				averageDecryptionTime += (stopTime - startTime) / decryptionCount;
//				System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
//				
//				System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);
//
////				PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
////				chatScreen.println(senderName + ": " + decryptedData);
//			}
//
//			else
//			{
//				System.out.println("Message discarded!");
//				decryptedData = "0";
//			}
//
////			if(clientName.equals("Broker"))
////			{
////				ProcessCommand(decryptedData, senderName);
////			}
//		}
//		
//		else
//		{
//			System.out.println("Digital signature could not be verified");
//		}
//	}
	
	//GCH
//	public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
//	{
//		String decryptedData = "";
//		++decryptionCount;
//
//		System.out.println("Message received by " + clientName + ": " + message);
//
//		//verify digital signature
//		if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
//		{
//			System.out.println("Digital signature verified :)");
//			
//			
//			long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//			long startTime = System.nanoTime();//start timer
//			decryptedData = decrypt(message);
//			message = CCMP_Decrypt(decryptedData, cipherBlockChainKey);
//			System.out.println("Decrypted Cipher Block Chain: " + message);
//
//			if(isMessageAuthentic(message, hmacSignature))
//			{				
//
//
//				long stopTime = System.nanoTime();// stop timer
//				long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//				long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//				System.out.println("Memory used during decryption: " + actualUsedMemory + " bytes");
//				System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
//				averageDecryptionTime += (stopTime - startTime) / decryptionCount;
//				System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
//				
//				System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);
//
////				PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
////				chatScreen.println(senderName + ": " + decryptedData);
//			}
//
//			else
//			{
//				System.out.println("Message discarded!");
//				decryptedData = "0";
//			}
//
////			if(clientName.equals("Broker"))
////			{
////				ProcessCommand(decryptedData, senderName);
////			}
//		}
//		
//		else
//		{
//			System.out.println("Digital signature could not be verified");
//		}
//	}

	//CGH
//		public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
//		{
//			String decryptedData = "";
//			++decryptionCount;
//
//			System.out.println("Message received by " + clientName + ": " + message);
//
//			//verify digital signature
//			if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
//			{
//				System.out.println("Digital signature verified :)");
//				
//				long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//				long startTime = System.nanoTime();//start timer
//
//				message = CCMP_Decrypt(message, cipherBlockChainKey);
//				System.out.println("Decrypted Cipher Block Chain: " + message);
//				decryptedData = decrypt(message);
//
//
//				if(isMessageAuthentic(decryptedData, hmacSignature))
//				{				
//					
//					long stopTime = System.nanoTime();// stop timer
//					long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//					long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//					System.out.println("Memory used during decryption: " + actualUsedMemory + " bytes");
//					System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
//					averageDecryptionTime += (stopTime - startTime) / decryptionCount;
//					System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
//					
//					System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);
//
////					PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
////					chatScreen.println(senderName + ": " + decryptedData);
//				}
//
//				else
//				{
//					System.out.println("Message discarded!");
//					decryptedData = "0";
//				}
//
////				if(clientName.equals("Broker"))
////				{
////					ProcessCommand(decryptedData, senderName);
////				}
//			}
//			
//			else
//			{
//				System.out.println("Digital signature could not be verified");
//			}
//		}
		
		//CHG
		public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
		{
			String decryptedData = "";
			++decryptionCount;

			System.out.println("Message received by " + clientName + ": " + message);

			//verify digital signature
			if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
			{
				System.out.println("Digital signature verified :)");
				
				long startTime = System.nanoTime();//start timer

				message = CCMP_Decrypt(message, cipherBlockChainKey);
				System.out.println("Decrypted Cipher Block Chain: " + message);



				if(isMessageAuthentic(message, hmacSignature))
				{	
					decryptedData = decrypt(message);					
					long stopTime = System.nanoTime();// stop timer
					System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
					averageDecryptionTime += (stopTime - startTime) / decryptionCount;
					System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
					
					System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);

//					PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
//					chatScreen.println(senderName + ": " + decryptedData);
				}

				else
				{
					System.out.println("Message discarded!");
					decryptedData = "0";
				}

//				if(clientName.equals("Broker"))
//				{
//					ProcessCommand(decryptedData, senderName);
//				}
			}
			
			else
			{
				System.out.println("Digital signature could not be verified");
			}
		}
		
		//HCG
//		public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
//		{
//			String decryptedData = "";
//			++decryptionCount;
//
//			System.out.println("Message received by " + clientName + ": " + message);
//
//			//verify digital signature
//			if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
//			{
//				System.out.println("Digital signature verified :)");
//				
//				long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//				long startTime = System.nanoTime();//start timer
//
//				if(isMessageAuthentic(message, hmacSignature))
//				{
//					message = CCMP_Decrypt(message, cipherBlockChainKey);
//					System.out.println("Decrypted Cipher Block Chain: " + message);
//					decryptedData = decrypt(message);	
//					
//					long stopTime = System.nanoTime();// stop timer
//					long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//					long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//					System.out.println("Memory used during decryption: " + actualUsedMemory + " bytes");
//					System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
//					averageDecryptionTime += (stopTime - startTime) / decryptionCount;
//					System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
//					
//					System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);
//
////					PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
////					chatScreen.println(senderName + ": " + decryptedData);
//				}
//
//				else
//				{
//					System.out.println("Message discarded!");
//					decryptedData = "0";
//				}
//
////				if(clientName.equals("Broker"))
////				{
////					ProcessCommand(decryptedData, senderName);
////				}
//			}
//			
//			else
//			{
//				System.out.println("Digital signature could not be verified");
//			}
//		}
	
	//HGC
//	public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
//	{
//		String decryptedData = "";
//		++decryptionCount;
//
//		System.out.println("Message received by " + clientName + ": " + message);
//
//		//verify digital signature
//		if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
//		{
//			System.out.println("Digital signature verified :)");
//			
//			long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//			long startTime = System.nanoTime();//start timer
//
//			if(isMessageAuthentic(message, hmacSignature))
//			{
//				decryptedData = decrypt(message);
//				message = CCMP_Decrypt(decryptedData, cipherBlockChainKey);
//				System.out.println("Decrypted Cipher Block Chain: " + message);	
//				
//				long stopTime = System.nanoTime();// stop timer
//				long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//				long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//				System.out.println("Memory used during decryption: " + actualUsedMemory + " bytes");
//				System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
//				averageDecryptionTime += (stopTime - startTime) / decryptionCount;
//				System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
//				
//				System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);
//
////				PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
////				chatScreen.println(senderName + ": " + decryptedData);
//			}
//
//			else
//			{
//				System.out.println("Message discarded!");
//				decryptedData = "0";
//			}
//
////			if(clientName.equals("Broker"))
////			{
////				ProcessCommand(decryptedData, senderName);
////			}
//		}
//		
//		else
//		{
//			System.out.println("Digital signature could not be verified");
//		}
//	}
		
		/******************** below are different versions of the same method used to perform the encryptions in different orders ***************************/

	//GHC
	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
	{
		String CCMP_encryptedMessage = "";
		++encryptionCount;
		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
		long startTime = System.nanoTime();
		
		encryptedMessage = Encrypt(message);//GCM
		HMAC_Sign(encryptedMessage);//HMAC
		CCMP_encryptedMessage = CCMP_Encrypt(encryptedMessage, cipherBlockChainKey);//CCMP
		
		long stopTime = System.nanoTime();
		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
		return CCMP_encryptedMessage;
	}
	
	//GCH
//	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
//	{
//		String CCMP_encryptedMessage = "";
//		++encryptionCount;
//		
//		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long startTime = System.nanoTime();
//		
//		encryptedMessage = Encrypt(message);//GCM
//		CCMP_encryptedMessage = CCMP_Encrypt(encryptedMessage, cipherBlockChainKey);//CCMP
//		HMAC_Sign(CCMP_encryptedMessage);//HMAC
//
//		
//		long stopTime = System.nanoTime();
//		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
//		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
//		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
//		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
//		return CCMP_encryptedMessage;
//	}
	
	//CGH
//	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
//	{
//		String CCMP_encryptedMessage = "";
//		++encryptionCount;
//		
//		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long startTime = System.nanoTime();
//		
//
//		CCMP_encryptedMessage = CCMP_Encrypt(message, cipherBlockChainKey);//CCMP
//		encryptedMessage = Encrypt(CCMP_encryptedMessage);//GCM
//		HMAC_Sign(encryptedMessage);//HMAC
//
//
//		
//		long stopTime = System.nanoTime();
//		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
//		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
//		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
//		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
//		
//		return encryptedMessage;
//	}
	
	//CHG
//	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
//	{
//		String CCMP_encryptedMessage = "";
//		++encryptionCount;
//		
//		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long startTime = System.nanoTime();
//		
//		CCMP_encryptedMessage = CCMP_Encrypt(message, cipherBlockChainKey);//CCMP
//		HMAC_Sign(CCMP_encryptedMessage);//HMAC
//		encryptedMessage = Encrypt(CCMP_encryptedMessage);//AES-GCM
//
//		
//		long stopTime = System.nanoTime();
//		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
//		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
//		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
//		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
//		return encryptedMessage;
//	}
	
	//HCG
//	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
//	{
//		String CCMP_encryptedMessage = "";
//		++encryptionCount;
//		long startTime = System.nanoTime();
//		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		
//
//		HMAC_Sign(message);//HMAC
//		CCMP_encryptedMessage = CCMP_Encrypt(message, cipherBlockChainKey);//CCMP
//		encryptedMessage = Encrypt(CCMP_encryptedMessage);//AES-GCM
//		
//		long stopTime = System.nanoTime();
//		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
//		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
//		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
//		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
//		return encryptedMessage;
//	}
	
	//HGC
//	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
//	{
//		String CCMP_encryptedMessage = "";
//		++encryptionCount;
//		
//		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long startTime = System.nanoTime();
//		
//
//		HMAC_Sign(message);//HMAC
//		encryptedMessage = Encrypt(message);//AES-GCM
//		CCMP_encryptedMessage = CCMP_Encrypt(encryptedMessage, cipherBlockChainKey);//CCMP
//		
//		long stopTime = System.nanoTime();
//		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
//		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
//		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
//		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
//		return CCMP_encryptedMessage;
//	}

	public static void GenerateAESKey() throws Exception 
	{
		int keySize = 0;
		
		System.out.println("symmetric key: " + symmetricKey);

		//determine AES key size based on random privateValue
		switch(symmetricKey % 3)
		{
		case 0:
			keySize = 128;
			break;

		case 1:
			keySize = 192;
			break;

		case 2:
			keySize = 255; //256;
			break;

		}
		
//		keySize = 128;

//		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//		keyGenerator.init(keySize);
//		key = keyGenerator.generateKey();
		System.out.println("key size: " + keySize);
		
		String str = Long.toBinaryString(keySize); //"1234567812345678";
		str += str;
		System.out.println("AES key string: " + str);
		key = new SecretKeySpec(str.getBytes(), "AES");
	}

	//	public SecretKey getKey()
	//	{
	//		return key;
	//	}
	//	
	//	public void setKey(SecretKey aesKey)
	//	{
	//		this.key = aesKey;
	//	}
	//	
//	public Cipher getEncryptionCipher()
//	{
//		return encryptionCipher;
//	}
//
//	public void setEncryptionCipher(Cipher encryptionCipher)
//	{
//		this.encryptionCipher = encryptionCipher;
//	}

	//turns byte into string and returns the string
	private static String encode(byte[] data) 
	{
		return Base64.getEncoder().encodeToString(data);
	}

	//turns string into byte and returns the byte
	private static byte[] decode(String data) 
	{
		return Base64.getDecoder().decode(data);
	}

//	public void Wait() throws InterruptedException
//	{
//		Thread.sleep(1);
//	}

}
