import java.io.File;
import java.io.FileOutputStream;
import java.security.Key;  
import java.security.NoSuchAlgorithmException;  

import javax.crypto.Cipher;  
import javax.crypto.KeyGenerator;  
import javax.crypto.SecretKey;  
import javax.crypto.spec.SecretKeySpec;  

//some predefined String that we have to convert to 1. key 2. 明文
//1. Class name: carannotationinfolongenough
//2. ApplicationKey:GQvxCLxantyoyl2Zo30XIpWyAtbVKa2uCbCSHNry
//3. ClientKey: g2PktGEOsVOUxp6PS5McI9FLNQrbAspF1xsX2MEz
//4. UserName:  AndroidUser
//5. Password:  notdefinedmaybenotexist


public class Mainclass {
	public static final String CLASSNAME="carannotationinfolongenough";
	public static final String APPLICATIONID="GQvxCLxantyoyl2Zo30XIpWyAtbVKa2uCbCSHNry";
	public static final String CLIENTKEY="g2PktGEOsVOUxp6PS5McI9FLNQrbAspF1xsX2MEz";
	public static final String USERNAME="AndroidUserForEncryptionUse";
	public static final String USERPASSWORD="notdefinedmaybenotexist";
	      
	    /** 
	     * 密钥算法 
	    */  
	    private static final String KEY_ALGORITHM = "AES";  
	      
	    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";  
	      
	    /** 
	     * 初始化密钥 
	     *  
	     * @return byte[] 密钥  
	     * @throws Exception 
	     */  
	    public static byte[] initSecretKey() {  
	        //返回生成指定算法的秘密密钥的 KeyGenerator 对象  
	        KeyGenerator kg = null;  
	        try {  
	            kg = KeyGenerator.getInstance(KEY_ALGORITHM);  
	        } catch (NoSuchAlgorithmException e) {  
	            e.printStackTrace();  
	            return new byte[0];  
	        }  
	        //初始化此密钥生成器，使其具有确定的密钥大小  
	        //AES 要求密钥长度为 128  
	        kg.init(128);  
	        //生成一个密钥  
	        SecretKey  secretKey = kg.generateKey();  
	        return secretKey.getEncoded();  
	    }  
	      
	    /** 
	     * 转换密钥 
	     *  
	     * @param key   二进制密钥 
	     * @return 密钥 
	     */  
	    private static Key toKey(byte[] key){  
	        //生成密钥  
	        return new SecretKeySpec(key, KEY_ALGORITHM);  
	    }  
	      
	    /** 
	     * 加密 
	     *  
	     * @param data  待加密数据 
	     * @param key   密钥 
	     * @return byte[]   加密数据 
	     * @throws Exception 
	     */  
	    public static byte[] encrypt(byte[] data,Key key) throws Exception{  
	        return encrypt(data, key,DEFAULT_CIPHER_ALGORITHM);  
	    }  
	      
	    /** 
	     * 加密 
	     *  
	     * @param data  待加密数据 
	     * @param key   二进制密钥 
	     * @return byte[]   加密数据 
	     * @throws Exception 
	     */  
	    public static byte[] encrypt(byte[] data,byte[] key) throws Exception{  
	        return encrypt(data, key,DEFAULT_CIPHER_ALGORITHM);  
	    }  
	      
	      
	    /** 
	     * 加密 
	     *  
	     * @param data  待加密数据 
	     * @param key   二进制密钥 
	     * @param cipherAlgorithm   加密算法/工作模式/填充方式 
	     * @return byte[]   加密数据 
	     * @throws Exception 
	     */  
	    public static byte[] encrypt(byte[] data,byte[] key,String cipherAlgorithm) throws Exception{  
	        //还原密钥  
	        Key k = toKey(key);  
	        return encrypt(data, k, cipherAlgorithm);  
	    }  
	      
	    /** 
	     * 加密 
	     *  
	     * @param data  待加密数据 
	     * @param key   密钥 
	     * @param cipherAlgorithm   加密算法/工作模式/填充方式 
	     * @return byte[]   加密数据 
	     * @throws Exception 
	     */  
	    public static byte[] encrypt(byte[] data,Key key,String cipherAlgorithm) throws Exception{  
	        //实例化  
	        Cipher cipher = Cipher.getInstance(cipherAlgorithm);  
	        //使用密钥初始化，设置为加密模式  
	        cipher.init(Cipher.ENCRYPT_MODE, key);  
	        //执行操作  
	        return cipher.doFinal(data);  
	    }  
	      
	      
	      
	    /** 
	     * 解密 
	     *  
	     * @param data  待解密数据 
	     * @param key   二进制密钥 
	     * @return byte[]   解密数据 
	     * @throws Exception 
	     */  
	    public static byte[] decrypt(byte[] data,byte[] key) throws Exception{  
	        return decrypt(data, key,DEFAULT_CIPHER_ALGORITHM);  
	    }  
	      
	    /** 
	     * 解密 
	     *  
	     * @param data  待解密数据 
	     * @param key   密钥 
	     * @return byte[]   解密数据 
	     * @throws Exception 
	     */  
	    public static byte[] decrypt(byte[] data,Key key) throws Exception{  
	        return decrypt(data, key,DEFAULT_CIPHER_ALGORITHM);  
	    }  
	      
	    /** 
	     * 解密 
	     *  
	     * @param data  待解密数据 
	     * @param key   二进制密钥 
	     * @param cipherAlgorithm   加密算法/工作模式/填充方式 
	     * @return byte[]   解密数据 
	     * @throws Exception 
	     */  
	    public static byte[] decrypt(byte[] data,byte[] key,String cipherAlgorithm) throws Exception{  
	        //还原密钥  
	        Key k = toKey(key);  
	        return decrypt(data, k, cipherAlgorithm);  
	    }  
	  
	    /** 
	     * 解密 
	     *  
	     * @param data  待解密数据 
	     * @param key   密钥 
	     * @param cipherAlgorithm   加密算法/工作模式/填充方式 
	     * @return byte[]   解密数据 
	     * @throws Exception 
	     */  
	    public static byte[] decrypt(byte[] data,Key key,String cipherAlgorithm) throws Exception{  
	        //实例化  
	        Cipher cipher = Cipher.getInstance(cipherAlgorithm);  
	        //使用密钥初始化，设置为解密模式  
	        cipher.init(Cipher.DECRYPT_MODE, key);  
	        //执行操作  
	        return cipher.doFinal(data);  
	    }  
	      
	    private static String  showByteArray(byte[] data){  
	        if(null == data){  
	            return null;  
	        }  
	        StringBuilder sb = new StringBuilder("{");  
	        for(byte b:data){  
	            sb.append(b).append(",");  
	        }  
	        sb.deleteCharAt(sb.length()-1);  
	        sb.append("}");  
	        return sb.toString();  
	    }  

	    public static String byte2String(byte[] bitearray){
	    	
	    	StringBuilder sb=new StringBuilder();
	    	for (byte b:bitearray) {
	    		sb.append(String.format("%02X", b));
			}
	    	return sb.toString();
	    }
	    
	    public static void GenerateShowing (String show_msg,String data,FileOutputStream output_k,FileOutputStream output_s) throws Exception{
	    	System.out.println();
	    	System.out.println();
	    	
	    	System.out.println("Content of: "+show_msg);
	    	
            byte[] key = initSecretKey();  
	        System.out.println("key："+showByteArray(key));   
	        System.out.println("key String:"+byte2String(key));
	        System.out.println("key 长度: length:"+key.length);
	        Key k = toKey(key);  
	    	
	        System.out.println(show_msg);
	        System.out.println("加密前数据: string:"+data);  
	        System.out.println("加密前数据: byte[]:"+showByteArray(data.getBytes()));  
	        System.out.println();  
	        byte[] encryptData = encrypt(data.getBytes(), k);  
	        System.out.println("加密后数据: byte[]:"+showByteArray(encryptData));  
	        System.out.println("加密后数据: hexStr:"+byte2String(encryptData));  
	        System.out.println("明文长度  : length"+encryptData.length);
	        System.out.println();  
	        byte[] decryptData = decrypt(encryptData, k);  
	        System.out.println("解密后数据: byte[]:"+showByteArray(decryptData));  
	        System.out.println("解密后数据: string:"+new String(decryptData));  
	        output_k.write(key);
	        output_s.write(encryptData);
	      //  FileOutputStream output=new FileOutputStream(new File("key"));
	    }
	    
	    public static void main(String[] args) throws Exception {  
	    	// Write a new File
	    	File keyFile=new File("key.dat");
	    	File showstringFile=new File("showString.dat");
	    	FileOutputStream output_key=new FileOutputStream(keyFile, true);
	    	FileOutputStream output_showString=new FileOutputStream(showstringFile,true);
	    	GenerateShowing("classname", CLASSNAME, output_key, output_showString);
	    	GenerateShowing("applicaitonID", APPLICATIONID, output_key, output_showString);
	    	GenerateShowing("clientkey", CLIENTKEY, output_key, output_showString);
	    	GenerateShowing("username", USERNAME, output_key, output_showString);
	    	GenerateShowing("userpassword", USERPASSWORD, output_key, output_showString);
	    	
	    	
	    	
	        output_key.close();
	        output_showString.close();
	    }  
	    
	    
	}  

