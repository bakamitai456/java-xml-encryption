package com.kosolart.xml.service;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyGenerator;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
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
import org.xml.sax.InputSource;

public class EncryptionService {

  public String encrypt(String xmlString) throws Exception{
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document xmlDoc = builder.parse(new InputSource(new StringReader(xmlString)));

    PrivateKey privateSignKey = loadPrivateKeyFromPkcs8();
    X509Certificate signCert = loadClientX509Certificate();

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

    X509Certificate encryptCert = loadCitiX509Certificate();
//    X509Certificate encryptCert = (X509Certificate) ks.getCertificate("payout-dev.wndv.co");
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
    return writer.getBuffer().toString();
  }

  private X509Certificate loadCitiX509Certificate() throws CertificateException, IOException {
    FileInputStream fis;
    fis = new FileInputStream("src/main/resources/openssl.crt");
    X509Certificate encryptCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
    fis.close();
    return encryptCert;
  }

  private X509Certificate loadClientX509Certificate() throws CertificateException, IOException {
    X509Certificate signCert;
    try (FileInputStream fis = new FileInputStream("src/main/resources/openssl.crt")) {
      signCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
      signCert.checkValidity();
    }

    return signCert;
  }

  private PrivateKey loadPrivateKeyFromPkcs8()
      throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
    try (FileInputStream fis = new FileInputStream("src/main/resources/private_key.der")) {
      PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(fis.readAllBytes(), "RSA");
      return KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec);
    }
  }
}
