package Ejecucion;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.KeyStore.SecretKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.security.cert.CertificateException;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import ServidorSeguro.Transformacion;

public class AppAgente {

	//CONSTANTES
	public static final String HOLA ="HOLA";
	public static final String INICIO ="INICIO";
	public static final String CERCLNT ="CERCLNT:";
	public static final String CERTSRV ="CERTSRV:";
	public static final String ALGORITMOS ="ALGORITMOS";
	public final static String ALGORITMO1="RC4";
	public final static String ALGORITMO2="RSA";
	public final static String ALGORITMO3="HMACMD5";
	public static final String ESTADO ="ESTADO";
	public static final String DATA ="DATA";
	public static final String OK ="OK";
	public static final String ERROR ="ERROR";
	public static final String SIGNATUREALGORITHM="SHA1withRSA";
	public static final String ACT1="ACT1";
	public static final String ACT2="ACT2";

	/**
	 * Cambiarla cada vez que se cambie de computador
	 */
	public static final String DIRECCIONIP ="192.168.0.16";
	private SecretKeySpec desKey;
	private KeyPair keyPair;
	private String mensActuRes;
	private PrintWriter escritor;
	private BufferedReader lector;
	private Socket socServ;
	private java.security.cert.X509Certificate certiCli;
	private java.security.cert.X509Certificate certiServ;
	private KeyPair keyPairServ;
	private PublicKey pubKeySer;
	private boolean estado;
	private String posicion;

	public AppAgente()
	{
		estado=true;
//		System.out.println("Va a entrar al metodo inicializar!");
		inicializar();
		if(estado!=true)
		{
			System.out.println("Error en el metodo inicializar, por culpa de una exception!");
			return;
		}
//		System.out.println("Va a entrar al metodo inicioStuff!");
		inicioStuff();
		if(estado!=true)
		{
			System.out.println("Respuesta de error de parte servidor em el metodo inicioStuff!");
			return;
		}
//		System.out.println("Va a entrar en el metodo Certificacion!");
		certificacion();
//		System.out.println("Se logor hacer el proceso de certifiacion!");
		if(estado!=true)
		{
			System.out.println("Respuesta de erronea de parte del servidor en el metodo certificacion!");
			return;
		}
//		System.out.println("Va a entrar al metodo de recibeLLaveSimetrica!");
		recibeLlaveSimetrica();
		if(estado!=true)
		{
			return;
		}
		manejoPosicion();
		

	}

	public static void main(String[] args) {

		new AppAgente();
	}

	/**
	 * Metodo que inicializa la comunicacion con el servidor en el puerto 1234
	 */
	public void inicializar()
	{
		try {
			//PARA CORRER EL SERVER TOCA IR POR CONSOLA (CMD) HASTA DONDE SE ENCUENTRA EL JAR DEL SERVER, Y CORRER ESE JAR POR MEDIO DEL SIGUIENTE COMANDO EN CONSOLA:
			//java -jar servidorIC20161/servidorNSIC20161(dependiendo de cual servidor se quiere correr).jar
			//Luego se da el puerto al cual se quiere que se conecte, que en este caso es el 1234
			//Conecciones al servidor y buffreaders y printwriter stuff
			socServ = new Socket("192.168.0.7", 8080);
			escritor = new PrintWriter(socServ.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader( socServ.getInputStream()));
			//Creacion de las llaves asimetricas del cliente
			Security.addProvider(new BouncyCastleProvider());
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITMO2);
			generator.initialize(1024);
			keyPair = generator.generateKeyPair();

		} catch (Exception e) {
			System.err.println("Exception: " + e.getMessage());
			estado=false;
			System.exit(1);
		}
	}

	/**
	 * Metodo en el que se inicia la transaccion con el servidor y se envian al servidor los algoritmos a utilizar para el cifrado simetrico y asimetrico y para el digest
	 */
	public void inicioStuff()
	{
		try {
			//Inicializa la transaccion con el servidor enviando hola y recibiendo de vuelta inicio
			escritor.println(HOLA);
			System.out.println(HOLA);
			String respuesta = lector.readLine();
			mensActuRes=respuesta;
			System.out.println(mensActuRes);
			if(respuesta.equals(INICIO))
			{
				//Se envian los algoritmos a usar
				escritor.println(ALGORITMOS+":"+ALGORITMO1+":"+ALGORITMO2+":"+ALGORITMO3);
				//Se espera que el servidor confirme que hay problema con la informacion enviada
				String respuesta2 = lector.readLine();
				mensActuRes=respuesta2;
				System.out.println(respuesta2);
				if(respuesta2.startsWith(ESTADO))
				{
					String[] res = respuesta2.split(":");
					if(!res[1].equals(OK))
					{
						estado=false;
					}
				}
				else
				{
					estado=false;
					throw new Exception("NO RESPODNIO LO QUE DEBIA RESPONDER EL SERVIDOR, en vez de lo esperado respondio:"+mensActuRes);
				}
			}else{
				estado=false;
				throw new Exception("NO RESPODNIO LO QUE DEBIA RESPONDER EL SERVIDOR, en vez de lo esperado respondio:"+mensActuRes);
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (Exception e)
		{
			e.printStackTrace();
			System.out.println(e);
		}
	}

	/**
	 * Metodo en el cual se envia el certificado del cliente y se recibe el certificado del servidor, se valida el certificado del servidor y se saca la llave publica del servidor que este contiene
	 */
	public void certificacion()
	{
		try {
			//Proceso en el que se avisa que se va a enviar al certificado del cliente, ademas se crea y envia el certificado del cliente
			escritor.println(CERCLNT);
			certiCli = certificado();
			byte[] mybyte = certiCli.getEncoded();
			socServ.getOutputStream().write(mybyte);
			socServ.getOutputStream().flush();

			//Se recibe el aviso del servidor
			String respuesta3 = lector.readLine();
			mensActuRes=respuesta3;
			System.out.println(respuesta3); 
			//Si el mensaje recibido efectivamente comienza con CERTSRV entonces se pasa a obtener el certificado y sacar la llave publica del servidor de este
			if(respuesta3.startsWith(CERTSRV))
			{
//				//Se obtiene el certificado
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				certiServ = (X509Certificate) cf.generateCertificate(socServ.getInputStream());

				//se valida el certificado, en caso de problemas se envia una Exception 
				certiServ.checkValidity();
				pubKeySer= certiServ.getPublicKey();
				
				//Si no sale exception se evnia que no hay problemas al servidor
				escritor.println(ESTADO+":"+OK);
				

			}else{
				estado=false;
				throw new Exception("No respondio bien el servidor en la parte de certificados, en el primer if, en vez de responder:"+CERTSRV+" respondio:"+ mensActuRes);
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Exception muy rara, si es que se da.");
			e.printStackTrace();
		}catch(CertificateException e){
			e.printStackTrace();

			escritor.println(ESTADO+":"+ERROR);
			estado=false;
			System.out.println("Certificate is Invalid!");
		}
		catch (Exception e)
		{
			e.printStackTrace();
			System.out.println(e);
		}

	}

	/**
	 * Metodo que genera un certificado digital con base a las datos del equipo y con la llave publica del cliente y el algoritmo de firma dados
	 * @return X509Certificate
	 */
	public java.security.cert.X509Certificate certificado()
	{
		X509Certificate cert=null;
		try {
			long ACC = System.currentTimeMillis();							  // time from which the certificate stars being valid in miliseconds
			Date startDate = new Date(ACC);    								  // time from which certificate is valid
			Date expiryDate = new Date(ACC+43200000);     					  // time after which certificate is not valid
			BigInteger serialNumber = new BigInteger("1994032219940906");     // serial number for certificate
			X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
			X500Principal              dnName = new X500Principal("CN=Test CA Certificate");
			certGen.setSerialNumber(serialNumber);
			certGen.setIssuerDN(dnName);
			certGen.setNotBefore(startDate);
			certGen.setNotAfter(expiryDate);
			certGen.setSubjectDN(dnName);                       // note: same as issuer
			certGen.setPublicKey(keyPair.getPublic());
			certGen.setSignatureAlgorithm("SHA1withRSA");
			cert = certGen.generate(keyPair.getPrivate(), "BC");

		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cert;
	}

	/**
	 * Metodo que se encarga de recibir la llave simetrica encryptada con la llave publica del cliente, desencryptarla, y responder al servidor con esa misma llave simetrica pero encryptada con la llave publica del mismo, que se obtuvo en el certificado del mismo
	 */
	public void recibeLlaveSimetrica()
	{
		try {
			//Lectura de la data que contiene la llave simetrica del servidor, cifrada por la llave privada del servidor
			String respuesta = lector.readLine();
			mensActuRes=respuesta;
			
			//Revizamos si el mensaje comienza con Data
			System.out.println(respuesta);
			if(respuesta.startsWith(DATA))
			{
				//Ya que si comienza con DATA, entonces se usa la llave privada del cliente para obtener la llave simetrica, despues de obtener la parte del mensaje que la contiene
				String[] res = respuesta.split(":");
				byte[] hexa = Transformacion.destransformar(res[1]);
				Cipher privateDecryptCipher = Cipher.getInstance(ALGORITMO2);
				privateDecryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
				byte[] llaveSimEnBytes = privateDecryptCipher.doFinal(hexa);
				//Se genera la llave simetrica y se guarda para su posterior uso
				desKey = new SecretKeySpec(llaveSimEnBytes, ALGORITMO1);

				//Se usa la llave publica del servidor consegida en el certificado para encriptar la llave simetrica consegida y enviarla al servidor 
				Cipher publicEncryptCipher = Cipher.getInstance(ALGORITMO2);
				publicEncryptCipher.init(Cipher.ENCRYPT_MODE, pubKeySer);
				byte[] llaveSimetricaEncriptada = publicEncryptCipher.doFinal(llaveSimEnBytes);
				String hexanoBytes2 = Transformacion.transformar(llaveSimetricaEncriptada);

				//Se envia la llave simetrica cifrada con la llave publica del servidor que obtuvimos en su certificado
				System.out.println(DATA+":"+hexanoBytes2);
				escritor.println(DATA+":"+hexanoBytes2);
				 
				//Leemos la siguiente entrada que nos debe decir el estado del servidor, y si fue aceptada
				String resp2= lector.readLine();
				
				//Revisa la respuesta y en base en esta continuamos o no con la operacion del programa
				System.out.println(resp2);
				if(resp2.startsWith(ESTADO))
				{
					String[] res1 = resp2.split(":");
					if(!res1[1].equals(OK))
					{
						estado=false;
						System.out.println("El servidor respondio con ERROR al final del mensaje de estado");
					}
				}else
				{
					estado=false;
					System.out.println("El servidor respondio erroneamente, el mensaje de respuesta no comenzaba con ESTADO");
				}

			}else{
				estado=false;
				System.out.println("El servidor respondio erroneamente, alguno de los mensajes no comenzaba con DATA");
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (Exception e)
		{
			e.printStackTrace();
			System.out.println(e);
		}
	}

	/**
	 * Metodo que se encarga de mandar los correspondientes mensajes de la posicion encriptados y el correspondiente con diges de la posicion
	 */
	public void manejoPosicion()
	{
		byte [] cipheredText;
		posicion = "41 24.2028, 2 10.4418";
		try{
			System.out.println(posicion);
			
			//-----------------ENCRYPTAMOS SIN HASHEAR EL MENSAJE CON CIFRADO SIMETRICO---------------------------
			//Los bytes que representan la posicion del cliente/agente
			byte [] clearText = posicion.getBytes();
			
			//Cifrado de la posicion
			Cipher cipher = Cipher.getInstance(ALGORITMO1);
			cipher.init(Cipher.ENCRYPT_MODE, desKey);
			cipheredText = cipher.doFinal(clearText);
			String s2 = Transformacion.transformar(cipheredText);
			
			//Envio de la posicion cifrada
			System.out.println(ACT1+":"+s2);
			escritor.println(ACT1+":"+s2);
			
			//-----------------ENCRYPTAMOS EL MENSAJE CON CIFRADO ASIMETRICO---------------------------------------
			
			//Digest de los bytes de la posicion del cliente, en este digest se usa la llave simetrica que se obtuvo anteriormente
			Mac mac = Mac.getInstance(ALGORITMO3);
			mac.init(desKey);
			byte[] hash = mac.doFinal(clearText);
			
			//Cifrado del hash de los bytes de la posicion
			Cipher cipher2 = Cipher.getInstance(ALGORITMO2);
			cipher2.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
			byte[] cifrado = cipher2.doFinal(hash);
			
			//Transformacion y envio del mensaje cifrado anteriormente
			String s3 = Transformacion.transformar(cifrado);
			escritor.println(ACT2+":"+s3);

			System.out.println("Se envio el mensaje cifrado que es:"+s3);
			 //Lee la linea de respuesta/estado del servidor
			String resp2= lector.readLine();
			System.out.println(resp2); 
			
			if(resp2.startsWith(ESTADO))
			{
				String[] res1 = resp2.split(":");
				if(!res1[1].equals(OK))
				{
					estado=false;
					System.out.println("El servidor respondio con ERROR al final del mensaje de estado");
				}
			}else
			{
				estado=false;
				System.out.println("El servidor respondio erroneamente, el mensaje de respuesta no comenzaba con ESTADO");
			}
		}
		catch(Exception e)
		{
			System.out.println("Exception en el metodo de envio de mensaje de posicion: " + e.getMessage());
		}

	}
}
