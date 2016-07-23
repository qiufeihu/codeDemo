package org.qfh.demo;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class QfhRSAUtil {
	/** 指定加密算法为DESede */
	private static String ALGORITHM = "RSA";
	/** 指定key的大小 */
	private static int KEYSIZE = 1024;
	/** 指定公钥存放文件 */
	private static String PUBLIC_KEY_FILE = "/Users/QiuFeihu/Work/test/public.key";
	/** 指定私钥存放文件 */
	private static String PRIVATE_KEY_FILE = "/Users/QiuFeihu/Work/test/private.key";

	/**
	 * 生成密钥对
	 */
	private static void generateKeyPair() throws Exception {
		/** RSA算法要求有一个可信任的随机数源 */
		SecureRandom sr = new SecureRandom();
		System.out.println("随机数字："+sr.nextDouble());
		/** 为RSA算法创建一个KeyPairGenerator对象 */
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
		
		/** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
		kpg.initialize(KEYSIZE, sr);
		/** 生成密匙对 */
		KeyPair kp = kpg.generateKeyPair();
		/** 得到公钥 */
		Key publicKey = kp.getPublic();
		String publicKeyStr = Base64.encodeBase64String(publicKey.getEncoded());
		System.out.println("公钥："+publicKeyStr);
		/** 得到私钥 */
		Key privateKey = kp.getPrivate();
		String privateKeyStr = Base64.encodeBase64String(privateKey.getEncoded());
		System.out.println("私钥："+privateKeyStr);
		/** 用对象流将生成的密钥写入文件 */
		FileOutputStream fos1 = new FileOutputStream(PUBLIC_KEY_FILE);
		FileOutputStream fos2 = new FileOutputStream(PRIVATE_KEY_FILE);
		fos1.write(publicKeyStr.getBytes());
		fos2.write(privateKeyStr.getBytes());
		/** 清空缓存，关闭文件输出流 */
		fos1.close();
		fos2.close();
	}

	/**
	 * 加密方法 source： 源数据
	 */
	public static String encrypt(String source) throws Exception {
		
		/** 将文件中的公钥对象读出 */
		byte[] buffer = readKeyFileToByteArray(PUBLIC_KEY_FILE);
        //创建Key
        KeyFactory keyFactory= KeyFactory.getInstance(ALGORITHM);  
        X509EncodedKeySpec keySpec= new X509EncodedKeySpec(buffer);  
        Key key = (RSAPublicKey) keyFactory.generatePublic(keySpec);

		/** 得到Cipher对象来实现对源数据的RSA加密 */
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] b = source.getBytes();
		/** 执行加密操作 */
		byte[] b1 = cipher.doFinal(b);
		BASE64Encoder encoder = new BASE64Encoder();
		return encoder.encode(b1);
	}

	/**
	 * 解密算法 cryptograph:密文
	 */
	public static String decrypt(String cryptograph) throws Exception {
		/** 将文件中的私钥对象读出 */
		byte[] buffer = readKeyFileToByteArray(PRIVATE_KEY_FILE);
		//创建Key
        KeyFactory keyFactory= KeyFactory.getInstance(ALGORITHM);  
        PKCS8EncodedKeySpec keySpec= new PKCS8EncodedKeySpec(buffer);  
        Key key = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
		/** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key);
		BASE64Decoder decoder = new BASE64Decoder();
		byte[] b1 = decoder.decodeBuffer(cryptograph);
		/** 执行解密操作 */
		byte[] b = cipher.doFinal(b1);
		return new String(b);
	}
	
	/**
	 * 读取文件中的秘钥并转换成二进制数组
	 * @param path
	 * @return
	 */
	public static byte[] readKeyFileToByteArray(String path){
		
		byte[] buffer = null;
		String str = "";
		FileInputStream fis = null;
		try{
			fis = new FileInputStream(path);
	        byte[] tempbytes = new byte[100];
	        int byteread = 0;
	        // 读入多个字节到字节数组中，byteread为一次读入的字节数
	        while ((byteread = fis.read(tempbytes)) != -1) {
	            str += new String(tempbytes, 0, byteread);
	        }
	        fis.close();
	        buffer = Base64.decodeBase64(str);
		}catch(Exception e){
			e.printStackTrace();
		}

		return buffer;
	}
	


	public static void main(String[] args) throws Exception {
		
		generateKeyPair();  //生成秘钥文件
		
		String source = "就是不告诉你！自己猜";// 要加密的字符串
		String cryptograph = encrypt(source);// 生成的密文
		System.out.println("加密后的数据："+cryptograph);

		String target = decrypt(cryptograph);// 解密密文
		System.out.println("解密后的数据："+target);
	}

}
