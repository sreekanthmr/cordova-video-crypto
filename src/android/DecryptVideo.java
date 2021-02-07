package cordova-plugin-video-decrypt;

import java.net.InetAddress;  
import java.net.InetSocketAddress;  
import java.net.ServerSocket;  
import java.net.SocketAddress;

import java.io.FileInputStream;
import java.io.FileOutputStrea;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This class echoes a string called from JavaScript.
 */
public class DecryptVideo extends CordovaPlugin {

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("stream")) {
            String filePath = args.getString(0);
            this.stream(filePath, callbackContext);
            return true;
        }
        return false;
    }

    private void stream(String filePath, CallbackContext callbackContext) {
        if (filePath != null && filePath.length() > 0) {
          string key = "12erdfcvbnhjui89";
          string iv = "90iojknmvbfger34";
            //Decrypt code goes here.....
           ServerSocket serverSocket = new ServerSocket();
           int rport = generateRandomPort();
            //serverSocket.bind(new InetSocketAddress("0.0.0.0", 9990));
           serverSocket.bind(new InetSocketAddress("0.0.0.0", rport));

            // this is a blocking call, control will be blocked until client sends the request
            Socket finalAccept = serverSocket.accept();
            OutputStream outputStream = finalAccept.getOutputStream();

            // open downloaded file
            FileInputStream inputStream = new FileInputStream(filePath);
            while ((count = inputStream.read(data, 0, readbyte)) != -1) {
               if (count < readbyte) {
                 if ((lenghtOfFile - total) > readbyte) {
                       while (true) {
                          int seccount = inputStream.read(data, pos, (readbyte - pos));
                              pos = pos + seccount;
                              if (pos == readbyte) {
                                 break;
                              }
                        }
                      }
                    }

             // encrypt data read before writing to output stream
             decryptedData = SimpleCrypto.decrypt(key, iv, readbyte);
             outputStream.write(decryptedData);
            }
            callbackContext.success("0.0.0.0:"+rport);
            //callbackContext.success(decryptedData);
        } else {
            callbackContext.error("Expected one non-empty string argument.");
        }
    }

    // function to encrypt and decrypt data bytes
    public class SimpleCrypto {
        public static byte[] encrypt(byte[] key, byte iv[], byte[] clear)
               throws Exception {
                SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
                Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

                IvParameterSpec ivspec = new IvParameterSpec(iv);

                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec);
                byte[] encrypted = cipher.doFinal(clear);
                return encrypted;
        }

        public static byte[] decrypt(byte[] key, byte[] iv, byte[] encrypted)
            throws Exception {
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec);
    
            byte[] decrypted = cipher.doFinal(encrypted);
            return decrypted;
        }
    }

    private static int generateRandomPort() {
     ServerSocket s = null;
  try {
       // ServerSocket(0) results in availability of a free random port
       s = new ServerSocket(0);
       return s.getLocalPort();
      } catch (Exception e) {
        throw new RuntimeException(e);
         } finally {
        assert s != null;
     try {
            s.close();
         } catch (IOException e) {
             e.printStackTrace();
         }
      }
  }
}
