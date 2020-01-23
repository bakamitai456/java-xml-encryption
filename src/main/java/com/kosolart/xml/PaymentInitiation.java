package com.kosolart.xml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.crypto.KeyGenerator;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class PaymentInitiation {

  public static void main(String[] args) {

    String payload = null; // pass payment Initiation payload

    String paymentResponse = null;
    try {
      String requestISOPayXMLPayload = generatePaymentInitXML(payload);

      String JKS_FILE_PATH = null; //Initialize with JKS file path -- For eg., “C:\\API\\Cert\\ClientKeyStore.jks”
      String KEYSTORE_PWD = null; //Initialize with Key store password; --- - For eg., “pass123”
      String CLIENT_SIGN_ALIAS = null; //Initialize with Client Sign certificate key alias
      String CITI_ENCRYPT_ALIAS = null;//Initialize with CITI's encryption certificate key alias

      String signedEncryptedPaymentInitRequest = encrypt(requestISOPayXMLPayload, JKS_FILE_PATH,
          KEYSTORE_PWD,
          CLIENT_SIGN_ALIAS, CITI_ENCRYPT_ALIAS);

      String SSL_CERT_PATH = null; //For eg., “C:\\API\\Cert\\SSL.p12”
      String SSL_PWD = null; //For eg., “password123”
      String PROXY_URL = null; //For eg., “webproxy.abc.net”
      int port = 0; //For eg.,8080
      String endUrl = null; // for eg,"https://tts.sandbox.apib2b.citi.com/citiconnect/sb/paymentservices/v1/payment/initiation"
      String clientId = null; //For eg., "9a9064359d1-ed9f53-4d40-8gfrb60-1e53456a53899df"
      String oAuth = null; //- For eg., “F5yR7jdsfrethzserQ8iN6tU7xQ5sX8rQ8ofghqwnP3fdslY0rJ8tQ8vO6hhI7eE4rA1nSui73d6”

      String responseISOPayXMLPayload = callPaymentInitiationAPI(signedEncryptedPaymentInitRequest,
          SSL_CERT_PATH,
          SSL_PWD, PROXY_URL, port, endUrl, clientId, oAuth);

      String CLIENT_DECRYPT_ALIAS = null; // Initialize with Client decryption certificate key alias
      String CITI_VERF_ALIAS = null; // Initialize with CITI's signing certificate key alias

      Document paymentDoc = decrypt(responseISOPayXMLPayload, JKS_FILE_PATH, KEYSTORE_PWD,
          CLIENT_DECRYPT_ALIAS,
          CITI_VERF_ALIAS);

      TransformerFactory ptf = TransformerFactory.newInstance();
      Transformer paymentTransformer = ptf.newTransformer();
      paymentTransformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
      StringWriter paymentWriter = new StringWriter();
      paymentTransformer.transform(new DOMSource(paymentDoc), new StreamResult(paymentWriter));
      String verifiedDecryptedPaymentResponse = StringEscapeUtils
          .unescapeXml(paymentWriter.getBuffer().toString());

      System.out.println("Payment Decrypted Response\n" + verifiedDecryptedPaymentResponse);

      paymentResponse = parseResponse(paymentDoc, "BASE64", "//Response/text()");

    } catch (Exception e) {
      System.err.println(e.getMessage());
    }

    System.out.println("Payment Response\n" + paymentResponse);

  }

  private static String generatePaymentInitXML(String isoPayInXML) {
    StringBuffer xmlStrSb = new StringBuffer();
    final char pem_array[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
        'O', 'P', 'Q',
        'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
        'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6',
        '7', '8', '9', '+', '/'};

// Encode the ISOPaymentXML

    byte inBuff[] = isoPayInXML.getBytes();
    int numBytes = inBuff.length;
    if (numBytes == 0) {
      return "";
    }
    byte outBuff[] = new byte[(numBytes - 1) / 3 + 1 << 2];
    int pos = 0;
    int len = 3;
    for (int j = 0; j < numBytes; j += 3) {
      if (j + 3 > numBytes) {
        len = numBytes - j;
      }
      if (len == 3) {
        byte a = inBuff[j];
        byte b = inBuff[j + 1];
        byte c = inBuff[j + 2];
        outBuff[pos++] = (byte) pem_array[a >>> 2 & 0x3f];
        outBuff[pos++] = (byte) pem_array[(a << 4 & 0x30) + (b >>> 4 & 0xf)];
        outBuff[pos++] = (byte) pem_array[(b << 2 & 0x3c) + (c >>> 6 & 3)];
        outBuff[pos++] = (byte) pem_array[c & 0x3f];
      } else if (len == 2) {
        byte a = inBuff[j];
        byte b = inBuff[j + 1];
        byte c = 0;
        outBuff[pos++] = (byte) pem_array[a >>> 2 & 0x3f];
        outBuff[pos++] = (byte) pem_array[(a << 4 & 0x30) + (b >>> 4 & 0xf)];
        outBuff[pos++] = (byte) pem_array[(b << 2 & 0x3c) + (c >>> 6 & 3)];
        outBuff[pos++] = 61;
      } else {
        byte a = inBuff[j];
        byte b = 0;
        outBuff[pos++] = (byte) pem_array[a >>> 2 & 0x3f];
        outBuff[pos++] = (byte) pem_array[(a << 4 & 0x30) + (b >>> 4 & 0xf)];
        outBuff[pos++] = 61;
        outBuff[pos++] = 61;
      }
    }

    String paymentBase64 = new String(outBuff);

    xmlStrSb.append("");
    xmlStrSb.append("");
    xmlStrSb.append(paymentBase64);
    xmlStrSb.append("");
    xmlStrSb.append("");

    return xmlStrSb.toString();
  }

  private static String encrypt(String requestXmlPayload, String keyStoreFilePath,
      String keyStorePwd,
      String clientSignKeyAlias, String citiEncryptKeyAlias) throws Exception {

    String signedEncryptedRequest = "";
    try {
// Load Keystore file having all certs

      KeyStore ks = KeyStore.getInstance("JKS");
      FileInputStream fis = new FileInputStream(keyStoreFilePath);
      ks.load(fis, keyStorePwd.toCharArray());
      fis.close();

// Getting the XML payload as Document object

      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document xmlDoc = builder.parse(new InputSource(new StringReader(requestXmlPayload)));

// Getting Private/Public Client Signing Key

      PrivateKey privateSignKey = (PrivateKey) ks
          .getKey(clientSignKeyAlias, keyStorePwd.toCharArray());
      X509Certificate signCert = (X509Certificate) ks.getCertificate(clientSignKeyAlias);
      signCert.checkValidity();

// Signing the XML Payload Document

      org.apache.xml.security.Init.init();

      ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setNamespaceAware(true);
      Element root = xmlDoc.getDocumentElement();
      XMLSignature sig = new XMLSignature(xmlDoc, "file:", XMLSignature.ALGO_ID_SIGNATURE_RSA);
      root.appendChild(sig.getElement());
      Transforms transforms = new Transforms(xmlDoc);
      transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
      transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
      sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

      KeyInfo info = sig.getKeyInfo();
      X509Data x509data = new X509Data(xmlDoc);
      x509data.add(new XMLX509IssuerSerial(xmlDoc, signCert));
      x509data.add(new XMLX509Certificate(xmlDoc, signCert));
      info.add(x509data);

      sig.sign(privateSignKey);

// Getting Public Citi Encryption Key

      X509Certificate encryptCert = (X509Certificate) ks.getCertificate(citiEncryptKeyAlias);
      encryptCert.checkValidity();
      PublicKey publicEncryptKey = encryptCert.getPublicKey();

// Encrypt the signed XML Payload Document

      String jceAlgorithmName = "DESede";
      KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
      Key symmetricKey = keyGenerator.generateKey();
      String algorithmURI = XMLCipher.RSA_v1dot5;
      XMLCipher keyCipher = XMLCipher.getInstance(algorithmURI);
      keyCipher.init(XMLCipher.WRAP_MODE, publicEncryptKey);
      EncryptedKey encryptedKey = keyCipher.encryptKey(xmlDoc, symmetricKey);
      Element rootElement = xmlDoc.getDocumentElement();
      algorithmURI = XMLCipher.TRIPLEDES;
      XMLCipher xmlCipher = XMLCipher.getInstance(algorithmURI);
      xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
      EncryptedData encryptedData = xmlCipher.getEncryptedData();
      KeyInfo keyInfo = new KeyInfo(xmlDoc);
      keyInfo.add(encryptedKey);
      encryptedData.setKeyInfo(keyInfo);
      xmlCipher.doFinal(xmlDoc, rootElement, false);

// Convert the document object to String value

      TransformerFactory tf = TransformerFactory.newInstance();
      Transformer transformer = tf.newTransformer();
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
      StringWriter writer = new StringWriter();
      transformer.transform(new DOMSource(xmlDoc), new StreamResult(writer));
      signedEncryptedRequest = writer.getBuffer().toString();

    } catch (Exception exception) {
      throw exception;

    }
    return signedEncryptedRequest;
  }

  private static String callPaymentInitiationAPI(String payInitPayloadSignedEncrypted,
      String sslCertFilePath,
      String certPwd, final String proxyURL, final int port, String payInitURL, String clientID,
      String oAuthToken) {
    String response = "";
    System.out.println("<<<<< &&&&& in callPaymentInitiationAPI &&&&& >>>>>> " + payInitURL);
    try {

      KeyStore clientStore = KeyStore.getInstance("PKCS12");
      clientStore.load(new FileInputStream(sslCertFilePath), certPwd.toCharArray());
      KeyManagerFactory kmf = KeyManagerFactory
          .getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(clientStore, certPwd.toCharArray());

      SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
      sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());

      HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

//      Client client = new Client(new URLConnectionClientHandler(new HttpURLConnectionFactory() {
//        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyURL, port));
//
//        public HttpURLConnection getHttpURLConnection(URL url) throws IOException {
//          return (HttpURLConnection) url.openConnection(proxy);
//        }
//      }), new DefaultClientConfig());
//      WebResource webResource = client.resource(payInitURL).queryParam("client_id", clientID);
//      Builder builder = webResource.type(MediaType.APPLICATION_XML);
//      builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + oAuthToken);
//      builder.header("payloadType", "urn:iso:std:iso:20022:tech:xsd:pain.001.001.03");
//      ClientResponse clientResponse = builder
//          .post(ClientResponse.class, payInitPayloadSignedEncrypted);
//      System.out.println("getHeaders() --> " + clientResponse.getHeaders());
//
//      response = clientResponse.getEntity(String.class);

    } catch (Exception exception) {
      exception.printStackTrace();
    }
    return response;
  }

  private static Document decrypt(String responseXMLPayload, String keyStoreFilePath,
      String keyStorePwd,
      String clientDecryptKeyAlias, String citiVerifyKeyAlias) throws Exception {
    Document decryptedDoc = null;
    try {
// Load Keystore file having all certs

      KeyStore ks = KeyStore.getInstance("JKS");
      FileInputStream fis = new FileInputStream(keyStoreFilePath);
      ks.load(fis, keyStorePwd.toCharArray());
      fis.close();

// Getting the XML payload as Document object

      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document xmlDoc = builder.parse(new InputSource(new StringReader(responseXMLPayload)));

// Getting Private/Public Client Decryption Key

      PrivateKey privateDecryptKey = (PrivateKey) ks
          .getKey(clientDecryptKeyAlias, keyStorePwd.toCharArray());
      X509Certificate decryptCert = (X509Certificate) ks.getCertificate(clientDecryptKeyAlias);
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

// Getting Public Citi Verification Key

      X509Certificate signVerifyCert = (X509Certificate) ks.getCertificate(citiVerifyKeyAlias);
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

// Convert the document object to String value

      /*
       * TransformerFactory tf = TransformerFactory.newInstance();
       * Transformer transformer = tf.newTransformer();
       * transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,
       * "yes"); StringWriter writer = new StringWriter();
       * transformer.transform(new DOMSource(xmlDoc), new
       * StreamResult(writer)); verifiedDecryptedResponse =
       * StringEscapeUtils.unescapeXml(writer.getBuffer().toString());
       */
    } catch (Exception exception) {
      exception.printStackTrace();
      throw exception;
    }
    return decryptedDoc;
  }

  private static String parseResponse(Document responeDoc, String type, String tagName)
      throws Exception {
    String response = "";
    XPath xpath = XPathFactory.newInstance().newXPath();

    String errorInResponse = "";
    Element docRoot = responeDoc.getDocumentElement();
    if (docRoot == null || docRoot.getNodeName() == null) {
      errorInResponse = "Response Message Doesn't have expected Information";
    } else {
      if (docRoot.getNodeName().equalsIgnoreCase("errormessage")) {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(responeDoc), new StreamResult(writer));
        errorInResponse = writer.getBuffer().toString();

        System.err.println("%%% errorInResponse %%%% " + errorInResponse);
      }
    }

/*if (!errorThrownRequired)
logger.info("Output Auth Response String ==> " , parseError);
else */
    if (errorInResponse.trim().length() > 0) {
      throw new Exception(errorInResponse);
    } else {

      NodeList nodes = (NodeList) xpath.compile(tagName)
          .evaluate(responeDoc, XPathConstants.NODESET);

      if (nodes != null && nodes.getLength() == 1) {
        response = (String) nodes.item(0).getNodeValue();
      }
      if ("BASE64".equals(type)) {
        response = new String(Base64.decodeBase64(response));
      }
    }
    return response;
  }
}