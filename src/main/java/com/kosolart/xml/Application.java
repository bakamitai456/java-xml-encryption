package com.kosolart.xml;

import com.kosolart.xml.service.DecryptionService;
import com.kosolart.xml.service.EncryptionService;

public class Application {

  public static void main(String[] args) throws Exception {
    String input = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        + "<oAuthToken\n"
        + "\txmlns=\"http://com.citi.citiconnect/services/types/oauthtoken/v1\">\n"
        + "\t<grantType>client_credentials</grantType>\n"
        + "\t<scope>/authenticationservices/v1</scope>\n"
        + "</oAuthToken>";

    EncryptionService encryptionService = new EncryptionService();
    String encryptedXmlMessage = encryptionService.encrypt(input);

    System.out.println(encryptedXmlMessage);

    DecryptionService decryptionService = new DecryptionService();
    String decryptedMessage = decryptionService.decrypt(encryptedXmlMessage);

    System.out.println(">>>>>>>> Decrypt <<<<<<<<");
    System.out.println(decryptedMessage);
  }
}
