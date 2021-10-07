package com.disusered;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaResourceApi;

import org.json.JSONArray;
import org.json.JSONException;

import android.net.Uri;
import android.content.Context;

import javax.crypto.Cipher;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


/**
 * This class encrypts and decrypts files using the Conceal encryption lib
 */
public class Safe extends CordovaPlugin {

  public static final String ENCRYPT_ACTION = "encrypt";
  public static final String DECRYPT_ACTION = "decrypt";

  private Context CONTEXT; 

  private OutputStream OUTPUT_STREAM;
  private InputStream INPUT_STREAM;

  private String FILE_NAME;
  private Uri SOURCE_URI;
  private File SOURCE_FILE;
  private File TEMP_FILE;

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext)
          throws JSONException {
    if (action.equals(ENCRYPT_ACTION) || action.equals(DECRYPT_ACTION)) {
      CordovaResourceApi resourceApi = webView.getResourceApi();

      String path = args.getString(0);
      String pass = args.getString(1);
      Uri normalizedPath = resourceApi.remapUri(Uri.parse(path));      
      String key = args.getString(1);      
      this.doAction(path,normalizedPath,key,action,callbackContext);
      return true;
    }
    return false;
  }
  private void doAction(String path,Uri normalizedPath,String key,String action,CallbackContext callbackContext){
    //File inputFile = new File(normalizedPath.toString());
    String[] encryptsplitString = path.split("/");
    File inputFile = new File(Uri.parse(normalizedPath.toString()).getPath());
    System.out.println("Path is: "+path);
    String Str =normalizedPath.toString();
    for (String retval: Str.split(".")) {
         System.out.println("test path is: "+retval);
      }
    //System.out.println("Encrypted Path is: "+path.lastIndexOf("/"));
    //System.out.println("Encrypted Path first string is: "+path.substring(0, path.lastIndexOf("/")));
    int lastIndex=path.lastIndexOf("/");
    //System.out.println("Encrypted Path last is: "+path.substring(lastIndex+1));
    File encryptedFile = new File(Uri.parse(path.substring(0, path.lastIndexOf("/"))+"/encrypted_"+path.substring(lastIndex+1)).getPath());
    File decryptedFile = new File(Uri.parse(path.substring(0, path.lastIndexOf("/"))+"/decrypted_"+path.substring(lastIndex+1)).getPath());
    
    if (action.equals(ENCRYPT_ACTION)) {
        this.encryptToNewFile(key,inputFile,encryptedFile, callbackContext);
        this.renameToOldFilename(inputFile, encryptedFile);
      } else if (action.equals(DECRYPT_ACTION)) {
        this.decryptToNewFile(key,inputFile,decryptedFile, callbackContext);
        this.renameToOldFilename(inputFile, decryptedFile);
      }
  }  
  private void encryptToNewFile(String key,File inputFile, File outputFile, CallbackContext callbackContext) {
        try (FileInputStream inputStream = new FileInputStream(inputFile); FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] inputBytes = new byte[4096];
            for (int n = inputStream.read(inputBytes); n > 0; n = inputStream.read(inputBytes)) {
                byte[] outputBytes = cipher.update(inputBytes, 0, n);
                outputStream.write(outputBytes);
            }
            byte[] outputBytes = cipher.doFinal();
            outputStream.write(outputBytes);
            inputStream.close();
            outputStream.close();
            callbackContext.success("success");
        } catch (Exception e) {
            callbackContext.error(e.getMessage());
            //e.printStackTrace();
        }
  }
  private void decryptToNewFile(String key,File input, File output, CallbackContext callbackContext) {
        try (FileInputStream inputStream = new FileInputStream(input); FileOutputStream outputStream = new FileOutputStream(output)) {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] buff = new byte[4096];
            for (int readBytes = inputStream.read(buff); readBytes > -1; readBytes = inputStream.read(buff)) {
                outputStream.write(cipher.update(buff, 0, readBytes));
            }
            outputStream.write(cipher.doFinal());
            inputStream.close();
            outputStream.close();
            callbackContext.success("success");
        } catch (Exception e) {
            callbackContext.error(e.getMessage());
            //e.printStackTrace();
        }
  }
  private void renameToOldFilename(File oldFile, File newFile) {
        if (oldFile.exists()) {
            oldFile.delete();
        }
        newFile.renameTo(oldFile);
  }  
}
