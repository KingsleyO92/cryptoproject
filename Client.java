//Written by Kingsley Obi
//March 2022

import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {
	String name;

		//Helper Class that continuosly receives incoming messages from the Socket.
		public class MessageReceiver extends Thread{
			private DataInputStream receiverInput;
			private SecretKey aesKey;
			private IvParameterSpec initVect;

			public MessageReceiver(DataInputStream receiverInput, SecretKey aesKey, IvParameterSpec initVect){
				this.receiverInput = receiverInput;
				this.aesKey = aesKey;
				this.initVect = initVect; 
			}

			@Override
			public void run(){
				try{
					String incomingMessage;
					while (true){
						incomingMessage = receiveMessage(receiverInput, aesKey, initVect);
						System.out.println(incomingMessage);
					}
				}
				catch (NoSuchAlgorithmException algExcep){
					System.out.println("Incorrect Algorithm Reference Passed in for Keys");
					algExcep.printStackTrace();
				}
				catch (IOException ioe){
					System.out.println("Stream Error");
					ioe.printStackTrace();
				}
				catch (InvalidKeyException e){
					System.out.println("Invalid key used for init");
					e.printStackTrace();
				}
				catch (IllegalBlockSizeException e){
					System.out.println("doFinal error");
					e.printStackTrace();
				}
				catch (NoSuchPaddingException e){
						System.out.println("Cipher getInstance didnt work");
						e.printStackTrace();
				}
				catch (BadPaddingException e){
					System.out.println("Encryption or Decryption Error");
					e.printStackTrace();
				}
				catch (InvalidAlgorithmParameterException e){
					System.out.println("Algorithm for AES is Invalid");
					e.printStackTrace();
				}
				
			}
		}





	public Client(String name){
		this.name = name;
	}

	//Helper Method for Encrypting and Sending Messages with AES
	static void sendMessage(DataOutputStream output, SecretKey aesKey, IvParameterSpec initVect, String outgoingMessage) 
	throws NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchPaddingException,
	IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException  {
		byte[] message = outgoingMessage.getBytes();
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, aesKey, initVect);
		byte[] encryptedMessage = cipher.doFinal(message);
		output.writeInt(encryptedMessage.length);
		output.write(encryptedMessage);
		output.flush();
	}


	//Helper Method for Receiving and Decrypting Messages with AES
	static String receiveMessage(DataInputStream input, SecretKey aesKey, IvParameterSpec initVect)
	throws NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException,
	NoSuchPaddingException, BadPaddingException,InvalidAlgorithmParameterException {
		int messageSize = input.readInt();
		byte[] encryptedMessage = new byte[messageSize];
		input.read(encryptedMessage);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, aesKey, initVect);
		byte[] result = cipher.doFinal(encryptedMessage);
		return new String(result);
	}


	public static void main (String args[]) {
		try {
			String clientName;

			//RSA Key Pair is generated to be sent to the Server
			//for the encryption of the AES and IV before sending
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair keyPair = generator.generateKeyPair();
			PrivateKey myPrivateKey = keyPair.getPrivate();
			PublicKey myPublicKey = keyPair.getPublic();

			Socket socket = new Socket(args[0], Integer.parseInt(args[1]));

			ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			//Public Key is received without encryption and reconstructed (Vulnerable Practice)
			output.writeObject(myPublicKey);
			output.flush();

			Scanner userInput = new Scanner(System.in);
			String incomingMessage;
			String outgoingMessage;


			//Data outputs are created for Sending and Receiving Messages
			DataOutputStream dataOutput = new DataOutputStream(socket.getOutputStream());
			DataInputStream dataInput = new DataInputStream(socket.getInputStream());

			//Receive and reconstruct AES Key & IV 
			//Both were decrypted using RSA
			int messageSize = dataInput.readInt();
			byte[] encryptedMessage = new byte[messageSize];
			dataInput.read(encryptedMessage);
			Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decryptCipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
			byte[] aesSpec = decryptCipher.doFinal(encryptedMessage);
			SecretKeySpec secretKey = new SecretKeySpec(aesSpec, "AES");

			int ivLength = dataInput.readInt();
			byte[] encryptedIV = new byte [ivLength];
			dataInput.read(encryptedIV);
			decryptCipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
			byte[] iv = decryptCipher.doFinal(encryptedIV);
			IvParameterSpec initVect = new IvParameterSpec(iv);




			incomingMessage = receiveMessage(dataInput,secretKey,initVect);
			System.out.println(incomingMessage);
			incomingMessage= receiveMessage(dataInput,secretKey, initVect);
			System.out.println(incomingMessage);

			clientName = userInput.nextLine();
			Client client = new Client(clientName);
			sendMessage(dataOutput, secretKey, initVect, clientName);

			incomingMessage= receiveMessage(dataInput,secretKey,initVect);
			System.out.println(incomingMessage);

			incomingMessage= receiveMessage(dataInput,secretKey, initVect);
			System.out.println(incomingMessage);

			incomingMessage= receiveMessage(dataInput,secretKey, initVect);
			System.out.println(incomingMessage);

			//Thread is started to receive Messages and Print to screen for user
			//While they are sre simultaneously typing
			MessageReceiver messageReceiver = client.new MessageReceiver(dataInput,secretKey, initVect);
			messageReceiver.start();

			while (true){
				outgoingMessage = userInput.nextLine();
				sendMessage(dataOutput,secretKey,initVect,clientName+" "+outgoingMessage);
			}
		}
		catch (UnknownHostException unkwnHstExcept){
			System.out.println("Incorrect IP Address for ServerSocket");
			unkwnHstExcept.printStackTrace();
		}
		catch (NoSuchAlgorithmException algExcep){
			System.out.println("Incorrect Algorithm Reference Passed in for Keys");
			algExcep.printStackTrace();
		}
		catch (IOException ioe){
			System.out.println("Streams Error");
			ioe.printStackTrace();
		}
		catch (NoSuchPaddingException e){
				System.out.println("Encryption/Decryption Error");
				e.printStackTrace();
		}
		catch (InvalidKeyException e){
			System.out.println("Invalid key used for init");
			e.printStackTrace();
		}
		
		catch (IllegalBlockSizeException e){
			System.out.println("doFinal error");
			e.printStackTrace();
		}
		
		catch (BadPaddingException e){
			System.out.println("Encryption/Decryption Error");
			e.printStackTrace();
		}
		
		catch (InvalidAlgorithmParameterException e){
			System.out.println("Wrong Algorithm for AES passed in");
			e.printStackTrace();
		}

	}



}

