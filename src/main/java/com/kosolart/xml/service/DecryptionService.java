package com.kosolart.xml.service;

import java.io.FileInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class DecryptionService {
  public String decrypt(String encryptedMessage) throws Exception{

    Document decryptedDoc = null;
    KeyStore ks = KeyStore.getInstance("pkcs12");
    FileInputStream fis = new FileInputStream("src/main/resources/openssl.pfx");
    ks.load(fis, "password".toCharArray());
    fis.close();

// Getting the XML payload as Document object

    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document xmlDoc = builder.parse(new InputSource(new StringReader(encryptedMessage)));

// Getting Private/Public Client Decryption Key

    PrivateKey privateDecryptKey = (PrivateKey) ks
        .getKey("payout-dev.wndv.co", "password".toCharArray());
    X509Certificate decryptCert = (X509Certificate) ks.getCertificate("payout-dev.wndv.co");
    decryptCert.checkValidity();

// Decrypt the encrypted & signed XML Response Payload Document

    org.apache.xml.security.Init.init();

    Element docRoot = xmlDoc.getDocumentElement();
    Node dataEL = null;
    Node keyEL = null;
    if ("http://www.w3.org/2001/04/xmlenc#".equals(docRoot.getNamespaceURI())
        && "EncryptedData".equals(docRoot.getLocalName())) {
      dataEL = docRoot;
    } else {
      NodeList childs = docRoot
          .getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData");
      if (childs == null || childs.getLength() == 0) {
        throw new Exception("Encrypted Data not found on XML Document while parsing to decrypt");
      }
      dataEL = childs.item(0);
    }
    if (dataEL == null) {
      throw new Exception("Encrypted Data not found on XML Document while parsing to decrypt");
    }
    NodeList keyList = ((Element) dataEL)
        .getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#",
            "EncryptedKey");
    if (keyList == null || keyList.getLength() == 0) {
      throw new Exception("Encrypted Key not found on XML Document while parsing to decrypt");
    }
    keyEL = keyList.item(0);
    XMLCipher cipher = XMLCipher.getInstance();
    cipher.init(XMLCipher.DECRYPT_MODE, null);
    EncryptedData encryptedData = cipher.loadEncryptedData(xmlDoc, (Element) dataEL);
    EncryptedKey encryptedKey = cipher.loadEncryptedKey(xmlDoc, (Element) keyEL);

    if (encryptedData != null && encryptedKey != null) {
      String encAlgoURL = encryptedData.getEncryptionMethod().getAlgorithm();
      XMLCipher keyCipher = XMLCipher.getInstance();
      keyCipher.init(XMLCipher.UNWRAP_MODE, privateDecryptKey);
      Key encryptionKey = keyCipher.decryptKey(encryptedKey, encAlgoURL);
      cipher = XMLCipher.getInstance();
      cipher.init(XMLCipher.DECRYPT_MODE, encryptionKey);
      decryptedDoc = cipher.doFinal(xmlDoc, (Element) dataEL);
    }
    decryptedDoc.normalize();


    X509Certificate signVerifyCert = (X509Certificate) ks.getCertificate("payout-dev.wndv.co");
    signVerifyCert.checkValidity();

// Verifying the signature of decrypted XML response Payload
// Document

    boolean verifySignStatus = false;
    NodeList sigElement = decryptedDoc
        .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#",
            "Signature");
    if (sigElement == null || sigElement.getLength() == 0) {
      throw new Exception("No XML Digital Signature Found - unable to check the signature");
    } else {
      String BaseURI = "file:";
      XMLSignature signature = new XMLSignature((Element) sigElement.item(0), BaseURI);

      KeyInfo keyInfo = signature.getKeyInfo();
      if (keyInfo == null) {
        throw new Exception("Could not locate KeyInfo element - unable to check the signature");
      } else {
        if (keyInfo.containsX509Data()) {
          X509Certificate certFromDoc = keyInfo.getX509Certificate();
          if (certFromDoc != null) {
            int enCodeCertLengthFrmDocCert = certFromDoc.getEncoded().length;
            int enCodeCertLengthTobeValidated = signVerifyCert.getEncoded().length;
            if (enCodeCertLengthFrmDocCert == enCodeCertLengthTobeValidated) {
              verifySignStatus = signature.checkSignatureValue(signVerifyCert);
            } else {
              throw new Exception(
                  "Signature Verification Failed as Cert available in XML & configured on Plugin Properties are different");
            }
          }
        } else {
          PublicKey pk = keyInfo.getPublicKey();
          if (pk != null) {
            verifySignStatus = signature.checkSignatureValue(signVerifyCert);
          } else {
            throw new Exception("X509 cert and PublicKey not found on signature of XML");
          }
        }
      }
      Element element = (Element) decryptedDoc
          .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
      element.getParentNode().removeChild(element);
    }
    if (!verifySignStatus) {
      throw new Exception("XML Signature Verification Failed");
    }
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer transformer = tf.newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,"yes"); StringWriter writer = new StringWriter();
    transformer.transform(new DOMSource(xmlDoc), new StreamResult(writer));
    return StringEscapeUtils.unescapeXml(writer.getBuffer().toString());
  }
}
