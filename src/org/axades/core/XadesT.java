package org.axades.core;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;

import org.axades.core.XadesUtil.DateUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.kxml2.io.KXmlSerializer;
import org.kxml2.kdom.Document;
import org.kxml2.kdom.Element;
import org.kxml2.kdom.Node;

import android.util.Log;

public class XadesT {
	//debug flagek
	private boolean enveloping = true;
	private boolean simplets = true;
	//Alapertelmezett parameterek
	String _PIN_code="1234567890";
	String alias="none";
	String _xmlns_Enveloping = "ns";
	String _digest_algorithm_URI = "http://www.w3.org/2000/09/xmldsig#sha1";
	String _signature_algorithm_URI = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    String xmlns_XAdES = "";
    String tsaUrl = "http://egtstamp.egroup.hu:80/tsa";
    String output_path = "/sdcard/";
    String keystore_path = null;
    
	byte[] _data;
	Document doc;
	KeyStore keystore;
	
    //XML nodeok amikre globalisan szukseges a referencia
    private Element signedInfo;
	private Vector<Element> dataObjectFormats;
	private Element signingCertificate;
	private Element signatureValue;
	private byte[] signatureByte;
	
	
	public XadesT(String signdatapath, String p12path, String p12pass) throws IOException{
		keystore_path = p12path;
		_PIN_code = p12pass; 
		
		//Adatok beolvasasa byte tombbe
		
		FileInputStream fis = new FileInputStream(signdatapath); 	
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
	    byte[] data = new byte[4096];
	    int count = fis.read(data);
	    while(count != -1)
	    {
	        dos.write(data, 0, count);
	        count = fis.read(data);
	    }
	    _data = baos.toByteArray();
		
		
		//XML init
	    
		doc = new Document();
		if (!enveloping) _xmlns_Enveloping="";
		
		//BouncyCastle provider hozzaadasa
		
		Security.addProvider(new BouncyCastleProvider());
	}
	public void initKeystore() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
		
		 keystore = KeyStore.getInstance("PKCS12", "BC"); 
		 keystore.load (new FileInputStream(keystore_path), _PIN_code.toCharArray()); 
		 Enumeration<String> aliases = keystore.aliases();
		 while(aliases.hasMoreElements()){	 
			 alias = aliases.nextElement();
		 }
	}
	
	////////////////////////
	//XADES SIGNATURE
	////////////////////////
	public void sign() throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, InvalidKeyException, SignatureException, CertificateEncodingException, IOException, TSPException, NoSuchProviderException{
		
		//Gyoker xml node
		
		Element envsig = doc.createElement("","ns:EnvelopingSignature");
		XadesUtil.set_xmlns(envsig, _xmlns_Enveloping);
		doc.addChild(Node.ELEMENT,envsig);
	    
	    /////////////////////////////////////
	    //ns:SignedObject ,DataObjectFormat
	    /////////////////////////////////////
	    
		Log.v("Xades","embedding to-be-signed contents and their metadata");
	    Vector<Element> signedObjects = getSignedObjects();
	    dataObjectFormats = getDataObjectFormats();
	    	    
        //////////////////////////////////
    	//ds:KeyInfo and SigningCertificate
    	//////////////////////////////////
	    
	    Element keyInfo = getKeyInfo();
	    signingCertificate = getSigningCertificate();
         
        //////////////////
    	//SignedProperties
    	//////////////////
	    
	    Element signedProperties = getSignedProperties();
         
        ///////////////////////////////
    	//ds:Reference in ds:SignedInfo
    	///////////////////////////////
	    
        Vector<Element> references = getReferences();
            
        
        //SignedProperties reference
        MessageDigest spdig = MessageDigest.getInstance("SHA-1");
        
        OutputStream fas = new ByteArrayOutputStream();
		KXmlSerializer serializer = new KXmlSerializer();	
		serializer.setOutput(fas, "UTF-8");
		signedProperties.write(serializer);
		serializer.flush();
		
		spdig.update(fas.toString().getBytes());
        
        byte[] spdigbytes = spdig.digest();
        byte[] spdigbytesb64 = org.bouncycastle.util.encoders.Base64.encode(spdigbytes);
        
        Element transform = doc.createElement("", "ds:Transform");
        transform.setAttribute(null, "Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        transform.addChild(Node.TEXT,"" );
        Element transforms = doc.createElement("", "ds:Transforms");
        transforms.addChild(Node.ELEMENT, transform);
        Element digestmethod2 = doc.createElement("", "ds:DigestMethod");
        digestmethod2.setAttribute(null,"Algorithm",_digest_algorithm_URI);
        digestmethod2.addChild(Node.TEXT,"");
        Element digestvalue = doc.createElement("", "ds:DigestValue");
        digestvalue.addChild(Node.TEXT, XadesUtil.toString(spdigbytesb64));
   	 	Element spreference = doc.createElement("", "ds:Reference");
   	 	
   	 	// Ez a verzió csak egy bemenetet tud aláírni
   	 	spreference.setAttribute(null, "Id", "EnvelopingSignature-0-Signature-0-SignedInfo-0-Reference-1");
        spreference.setAttribute(null, "Type", "http://uri.etsi.org/01903#SignedProperties");
        spreference.setAttribute(null, "URI", "#EnvelopingSignature-0-Signature-0-Object-0-QualifyingProperties-0-SignedProperties-0");
        spreference.addChild(Node.ELEMENT, transforms);
        spreference.addChild(Node.ELEMENT, digestmethod2);
        spreference.addChild(Node.ELEMENT, digestvalue);
        references.add(spreference);
        
        //Creating SignedInfo element and adding object references
        signedInfo = getSignedInfo();   
        
        for( Element var:references){
        	 signedInfo.addChild(Node.ELEMENT,var);        	 
        }
        
        ///////////////////
    	//ds:SignatureValue
    	///////////////////

        signatureValue = getSignatureValue();

        ////////////////////
        //SignatureTimeStamp
    	////////////////////
        
        Element signatureTimeStamp = getSignatureTimeStamp();
                   
        //////////////////////////////////////////////
        //CertificateValues and CompleteCertificateRefs
        //////////////////////////////////////////////

        Element completeCertificateRefs = getCompleteCertificateRefs();
        Element certificateValues = getCertificateValues();
        
  
        Log.v("Xades","embedding certificates of certificate chain and their metadata (user signer and timestamp signer");
                 
         
        ///////////
        //ds:Object
    	///////////

    	//creating structure of unsigned metadata     
    	Element unsignedSignatureProperties = doc.createElement("","UnsignedSignatureProperties");
        
    	/////////////////////
        // SignatureTimeStamp
        /////////////////////
    	unsignedSignatureProperties.addChild(Node.ELEMENT,signatureTimeStamp);

        //////////////////////////
        // CompleteCertificateRefs
        //////////////////////////
    	unsignedSignatureProperties.addChild(Node.ELEMENT,completeCertificateRefs);

        /////////////////
        // $CertificateValues

        unsignedSignatureProperties.addChild(Node.ELEMENT,certificateValues);

        //////////////////
        //UnsignedProperties
        ///////////////////
        Element unsignedProperties = doc.createElement("","UnsignedProperties");
        unsignedProperties.setAttribute(null,"Id","EnvelopingSignature-0-Signature-0-Object-0-QualifyingProperties-0-UnsignedProperties-0");
        unsignedProperties.addChild(Node.ELEMENT,unsignedSignatureProperties);


        Element qualifyingProperties = doc.createElement("","QualifyingProperties");
    	qualifyingProperties.setAttribute(null,"Id", "EnvelopingSignature-0-Signature-0-Object-0-QualifyingProperties-0");
        qualifyingProperties.setAttribute(null,"Target", "#EnvelopingSignature-0-Signature-0");


        qualifyingProperties.addChild(Node.ELEMENT,signedProperties);
        qualifyingProperties.addChild(Node.ELEMENT,unsignedProperties);

        Element object = doc.createElement("","ds:Object");
        XadesUtil.set_xmlns(object, _xmlns_Enveloping);

        object.setAttribute(null,"Id","EnvelopingSignature-0-Signature-0-Object-0");
        object.addChild(Node.ELEMENT,qualifyingProperties);



    	
        //////////////
        //SIGNATURE
        //////////
        Element signature = doc.createElement("","ds:Signature");
        signature.setAttribute(null,"Id","EnvelopingSignature-0-Signature-0");
        signature.setAttribute(null,"xmlns","http://uri.etsi.org/01903/v1.3.2#");
        signature.setAttribute(null,"xmlns:ds","http://www.w3.org/2000/09/xmldsig#");
      
        signature.addChild(Node.ELEMENT,signedInfo);

        signature.addChild(Node.ELEMENT,signatureValue);

        signature.addChild(Node.ELEMENT,keyInfo);

        signature.addChild(Node.ELEMENT,object);

      
        envsig.setAttribute(null,"Id","EnvelopingSignature-0");
        
        for (Element so:signedObjects){
        	envsig.addChild(Node.ELEMENT, so);
        }
        envsig.addChild(Node.ELEMENT,signature);
      
        XadesUtil.XMLOutput(doc, output_path,  enveloping, simplets);
      	 
		
	
	}
	
	/*
	 * Reszfeladatokhoz tarozo kodreszek
	 * 
	 */
	
	
	/////////////////////////////////////
	//ns:SignedObject
	/////////////////////////////////////
	private Vector<Element> getSignedObjects() throws UnsupportedEncodingException{
		Log.v("Xades","embedding to-be-signed contents and their metadata");

	    Element signedObject = null;
		
	    
	    Vector<Element> signedObjects = new Vector<Element>();
	   
	    
	    
	    String MimeType_value = "";
	    byte[] data_base64encoded = org.bouncycastle.util.encoders.Base64.encode(_data);

	    signedObject =  doc.createElement("","ns:SignedObject");
	    XadesUtil.set_xmlns(signedObject, _xmlns_Enveloping);
	    signedObject.setAttribute(null,"Id", "EnvelopingSignature-0-SignedObject-0");
	    signedObject.setAttribute(null,"MimeType", MimeType_value);

	    signedObject.addChild(Node.TEXT, new String(data_base64encoded,"UTF-8"));
	    signedObjects.addElement(signedObject);
	    

	   
		return signedObjects;
	}
	//////////////////
	//DataObjectFormat
	//////////////////
    private Vector<Element> getDataObjectFormats(){
    	Element dataObjectFormat = null;
    	Element description = null;
	    Element mimeType = null; 
	    Vector<Element> dataObjectFormats = new Vector<Element>();
	    String MimeType_value = "";
	    String ObjectReference = "EnvelopingSignature-0-Signature-0-SignedInfo-0-Reference-0";

	    description = doc.createElement("","Description");
	    description.addChild(Node.TEXT,"test.xml");

	    mimeType = doc.createElement("","MimeType");
	    mimeType.addChild(Node.TEXT,MimeType_value);
    	dataObjectFormat = doc.createElement("","DataObjectFormat");
 	    dataObjectFormat.setAttribute(null,"ObjectReference","#"+ObjectReference);
 	    dataObjectFormat.addChild(Node.ELEMENT,description);
 	    dataObjectFormat.addChild(Node.ELEMENT,mimeType);
 	    dataObjectFormats.addElement(dataObjectFormat);
 	    return dataObjectFormats;
    }
    //////////////////
    //KeyInfo
    //////////////////
    private Element getKeyInfo() throws KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException{
    	Log.v("Xades","embedding signer certificate and its metadata");

        Certificate cert = keystore.getCertificate(alias);
		X509Certificate xcert = (X509Certificate) cert;
		
		String X509IssuerName_value = xcert.getIssuerDN().toString();     
        String X509SerialNumber_value = xcert.getSerialNumber().toString();
        String X509Certificate_value = XadesUtil.toString(org.bouncycastle.util.encoders.Base64.encode(xcert.getEncoded()));//filter_content_base64(file_read(_path_content+"certificate_pem.txt"));    
        //X509IssuerName
   	 	Element X509IssuerName = doc.createElement("","ds:X509IssuerName");
   	 	X509IssuerName.addChild(Node.TEXT,X509IssuerName_value);
   	 	//X509SerialNumber
   	 	Element X509SerialNumber = doc.createElement("","ds:X509SerialNumber");
        X509SerialNumber.addChild(Node.TEXT,X509SerialNumber_value);
        //X509IssuerSerial
        Element X509IssuerSerial = doc.createElement("","ds:X509IssuerSerial");
        X509IssuerSerial.addChild(Node.ELEMENT,X509IssuerName);
        X509IssuerSerial.addChild(Node.ELEMENT,X509SerialNumber);
        //X509Certificate
   	 	Element X509CertificateElem = doc.createElement("","ds:X509Certificate");
        X509CertificateElem.addChild(Node.TEXT,X509Certificate_value);
        //X509Data
   	 	Element X509Data = doc.createElement("","ds:X509Data");
        X509Data.addChild(Node.ELEMENT,X509IssuerSerial);
        X509Data.addChild(Node.ELEMENT,X509CertificateElem);
        //keyinfo
        Element keyInfo = doc.createElement("","ds:KeyInfo");
   	 	XadesUtil.set_xmlns(keyInfo, _xmlns_Enveloping);
        keyInfo.setAttribute(null,"Id","EnvelopingSignature-0-Signature-0-KeyInfo-0");
        keyInfo.addChild(Node.ELEMENT,X509Data);
        
        return keyInfo;
    	
    }
    ////////////////////
    //SigningCertificate
    ////////////////////
	private Element getSigningCertificate() throws NoSuchAlgorithmException, KeyStoreException, CertificateEncodingException {

        Log.v("Xades","embedding signer certificate and its metadata");

        Certificate cert = keystore.getCertificate(alias);
		X509Certificate xcert = (X509Certificate) cert;
		String X509IssuerName_value = xcert.getIssuerDN().toString();
        
        String X509SerialNumber_value = xcert.getSerialNumber().toString();
        
        byte[] certificate_der = xcert.getEncoded();
   	 	MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        messageDigest.update(certificate_der);
        byte[] bufout = messageDigest.digest();
        byte[] data_shabinary_base64encoded = org.bouncycastle.util.encoders.Base64.encode(bufout);
        //DigestMethod
        Element digestMethod = doc.createElement("","ds:DigestMethod");
        digestMethod.setAttribute(null,"Algorithm",_digest_algorithm_URI);
        digestMethod.addChild(Node.TEXT, "");
        //DigestValue
        Element digestValue = doc.createElement("","ds:DigestValue");
        digestValue.addChild(Node.TEXT,XadesUtil.toString(data_shabinary_base64encoded));
        //CertDigest
        Element certDigest = doc.createElement("","CertDigest");
        certDigest.addChild(Node.ELEMENT,digestMethod);
        certDigest.addChild(Node.ELEMENT,digestValue);
        //X509IssuerName
   	 	Element X509IssuerName = doc.createElement("","ds:X509IssuerName");
   	 	X509IssuerName.addChild(Node.TEXT,X509IssuerName_value);
   	    //X509SerialNumber
        Element X509SerialNumber = doc.createElement("","ds:X509SerialNumber");
        X509SerialNumber.addChild(Node.TEXT,X509SerialNumber_value);
        //IssuerSerial
        Element issuerSerial = doc.createElement("","IssuerSerial");
        issuerSerial.addChild(Node.ELEMENT,X509IssuerName);
        issuerSerial.addChild(Node.ELEMENT,X509SerialNumber); 
        //Cert
        Element certelem = doc.createElement("","Cert");
        certelem.setAttribute(null,"URI","#EnvelopingSignature-0-Signature-0-Object-0-QualifyingProperties-0-UnsignedProperties-0-UnsignedSignatureProperties-0-CertificateValues-0-EncapsulatedX509Certificate-0");
        certelem.addChild(Node.ELEMENT,certDigest);
        certelem.addChild(Node.ELEMENT,issuerSerial);
        //SingingCertificate
        Element signingCertificate = doc.createElement("","SigningCertificate");
        signingCertificate.addChild(Node.ELEMENT,certelem);
        return signingCertificate;

        
	}
	////////////////////
    //SignedProperties
    ////////////////////
	private Element getSignedProperties() {
		Log.v("Xades","creating to-be-signed metadata structure");
        //SigningTime
		Element signingTime = doc.createElement("","SigningTime");
        String datetime = DateUtils.nowxmldt();
        signingTime.addChild(Node.TEXT,datetime);
        //SignaturePolicyIdentifier
        Element signaturePolicyIdentifier = doc.createElement("","SignaturePolicyIdentifier");
        Element signaturePolicyImplied = doc.createElement("","SignaturePolicyImplied");
        signaturePolicyImplied.addChild(Node.TEXT, "");
        signaturePolicyIdentifier.addChild(Node.ELEMENT,signaturePolicyImplied);
        //SignedSignatureProperties
        Element signedSignatureProperties = doc.createElement("","SignedSignatureProperties");
        signedSignatureProperties.addChild(Node.ELEMENT,signingTime);
        signedSignatureProperties.addChild(Node.ELEMENT,signingCertificate);
        signedSignatureProperties.addChild(Node.ELEMENT,signaturePolicyIdentifier);
        //SignedDataObjectProperties
        Element signedDataObjectProperties = doc.createElement("","SignedDataObjectProperties");
        for (Element var : dataObjectFormats) {
       	 signedDataObjectProperties.addChild(Node.ELEMENT,var);
        }
        //SignedProperties
        Element signedProperties = doc.createElement("","SignedProperties");
        XadesUtil.set_xmlns(signedProperties, _xmlns_Enveloping);
        signedProperties.setAttribute(null,"Id","EnvelopingSignature-0-Signature-0-Object-0-QualifyingProperties-0-SignedProperties-0");
        signedProperties.addChild(Node.ELEMENT,signedSignatureProperties);
        signedProperties.addChild(Node.ELEMENT,signedDataObjectProperties);
        
        return signedProperties;
	}

	////////////////////
	//Reference
	////////////////////
	private Vector<Element> getReferences() throws NoSuchAlgorithmException {
		Log.v("Xades","creating hashes of to-be-signed structures");
		Element transform = null;
        Element transforms = null;
        Element digestMethod = null;
        byte[] data_shabinary_base64encoded = null;
        Element digestValue = null;
		
		//TODO: for every data
		Vector<Element> references = new Vector<Element>();
        //Transforms
        transform = doc.createElement("","ds:Transform");
        transform.setAttribute(null,"Algorithm","http://www.w3.org/2000/09/xmldsig#base64");
        transform.addChild(Node.TEXT, "");
        transforms = doc.createElement("","ds:Transforms");
        transforms.addChild(Node.ELEMENT,transform);
        //DigestMethod
        digestMethod = doc.createElement("","ds:DigestMethod");
        digestMethod.setAttribute(null,"Algorithm", _digest_algorithm_URI);
        digestMethod.addChild(Node.TEXT,"");
        //DigestValue
        
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        messageDigest.update(_data);
        byte[] bufout =  messageDigest.digest();
        
        data_shabinary_base64encoded = org.bouncycastle.util.encoders.Base64.encode(bufout);
        digestValue = doc.createElement("","ds:DigestValue");
        digestValue.addChild(Node.TEXT,XadesUtil.toString(data_shabinary_base64encoded));
        //Reference              
        Element reference = doc.createElement("","ds:Reference");
        reference.setAttribute(null,"Id","EnvelopingSignature-0-Signature-0-SignedInfo-0-Reference-0");
        reference.setAttribute(null,"URI","#EnvelopingSignature-0-SignedObject-0");
        reference.addChild(Node.ELEMENT,transforms);
        reference.addChild(Node.ELEMENT,digestMethod);
        reference.addChild(Node.ELEMENT,digestValue);
        references.addElement(reference);

    	return references;
		}
		
	///////////////////
	//SignedInfo
	//////////////////
	private Element getSignedInfo(){
		//CanonicalizationMethod
		Element canonicalizationMethod = doc.createElement("","ds:CanonicalizationMethod");
        canonicalizationMethod.setAttribute(null,"Algorithm","http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        canonicalizationMethod.addChild(Node.TEXT, "");
        //SignatureMethod
        Element signatureMethod = doc.createElement("","ds:SignatureMethod");
        signatureMethod.setAttribute(null,"Algorithm",_signature_algorithm_URI);
        signatureMethod.addChild(Node.TEXT, "");
        //SignedInfo
        Element signedInfo = doc.createElement("","ds:SignedInfo");    
        XadesUtil.set_xmlns(signedInfo, _xmlns_Enveloping);
        signedInfo.setAttribute(null,"Id","EnvelopingSignature-0-Signature-0-SignedInfo-0");
        signedInfo.addChild(Node.ELEMENT,canonicalizationMethod);
        signedInfo.addChild(Node.ELEMENT,signatureMethod);
        return signedInfo;
	}

	////////////////////
	//SignatureValue
	//////////////////
	private Element getSignatureValue() throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, SignatureException, InvalidKeyException, IOException{
		Log.v("Xades","creating encoded hash of to-be-signed structures");
        
        PrivateKey privateKey = (PrivateKey)keystore.getKey(alias, _PIN_code.toCharArray());
        //encrypting signedinfo with private key
        Signature sig = Signature.getInstance("SHA1withRSA");

   	 	sig.initSign(privateKey);
   	 	
   	 	OutputStream fas = new ByteArrayOutputStream();
		KXmlSerializer serializer = new KXmlSerializer();	
		serializer.setOutput(fas, "UTF-8");
		signedInfo.write(serializer);
		serializer.flush();
   	 	
   	 	sig.update(fas.toString().getBytes());
   	 	
   	 	
   	 	signatureByte = sig.sign();
   	 
        //String signatureValue_value = base64_encode(file_read($path_content . "SignatureValue.txt"));
   	 	byte[] signatureValue_encoded = org.bouncycastle.util.encoders.Base64.encode(signatureByte);
   	 	String signatureValue_value =XadesUtil.toString(signatureValue_encoded);
   	 	//SignatureValue
        Element signatureValue = doc.createElement("","ds:SignatureValue");
   	 	XadesUtil.set_xmlns(signatureValue, _xmlns_Enveloping);
        signatureValue.setAttribute(null,"Id","EnvelopingSignature-0-Signature-0-SignatureValue-0");
        signatureValue.addChild(Node.TEXT,signatureValue_value);
		return signatureValue;
	}

	////////////////////
	//SignatureTimestamp
	////////////////////
	private Element getSignatureTimeStamp() throws NoSuchAlgorithmException, IOException, TSPException, NoSuchProviderException{
		
		Log.v("Xades","Signature timestamp");
    	
	    //CanonicalizationMethod
        Element canonicalizationMethod = doc.createElement("","ds:CanonicalizationMethod");
        canonicalizationMethod.setAttribute(null,"Algorithm","http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        canonicalizationMethod.addChild(Node.TEXT,"");
        //EncapsulatedTimeStamp
        Element encapsulatedTimeStamp = doc.createElement("","EncapsulatedTimeStamp");
        encapsulatedTimeStamp.setAttribute(null,"Id","EnvelopingSignature-0-Signature-0-Object-0-QualifyingProperties-0-UnsignedProperties-0-UnsignedSignatureProperties-0-SignatureTimeStamp-0-EncapsulatedTimeStamp-0");
        
        //Creating bytearray of signaturevalue object
        OutputStream fas = new ByteArrayOutputStream();
		KXmlSerializer serializer = new KXmlSerializer();	
		serializer.setOutput(fas, "UTF-8");
		signatureValue.write(serializer);
		serializer.flush();
        
        //String tstokenb64 = TSRequest.xades_ts_req(tsaUrl, fas.toString().getBytes(), simplets, bypassts);
		
		String tstokenb64 = TSHexRequest.xades_hex_ts_req(tsaUrl, fas.toString().getBytes());
        
        encapsulatedTimeStamp.addChild(Node.TEXT,tstokenb64);
        //SignatureTimeStamp
        Element signatureTimeStamp = doc.createElement("","SignatureTimeStamp");
        signatureTimeStamp.setAttribute(null,"xmlns","http://uri.etsi.org/01903/v1.3.2#");
        signatureTimeStamp.setAttribute(null,"xmlns:ds","http://www.w3.org/2000/09/xmldsig#");
        signatureTimeStamp.setAttribute(null,"Id","EnvelopingSignature-0-Signature-0-Object-0-QualifyingProperties-0-UnsignedProperties-0-UnsignedSignatureProperties-0-SignatureTimeStamp-0");         signatureTimeStamp.addChild(Node.ELEMENT,canonicalizationMethod);
        signatureTimeStamp.addChild(Node.ELEMENT,encapsulatedTimeStamp);
		return signatureTimeStamp;
	}
	///////////////////
	//CompleteCertificateRefs
	///////////////////
	private Element getCompleteCertificateRefs() throws KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException{
		 Certificate[] certchain = keystore.getCertificateChain(alias);
		 
		//CertRefs
		 Element certRefs = doc.createElement("", "CertRefs");
		 
		 int counter = 0;
		 for(Certificate c:certchain){
			 X509Certificate xcert = (X509Certificate) c;
			 
			 //X509IssuerName
			 Element X509IssuerName = doc.createElement("", "ds:X509IssuerName");
			 X509IssuerName.addChild(Node.TEXT, xcert.getIssuerDN().getName());
			 //X509SerialNumber
			 Element X509SerialNumber = doc.createElement("", "ds:X509SerialNumber");
			 X509SerialNumber.addChild(Node.TEXT, xcert.getSerialNumber().toString());
			 
			 //IssuerSerial
			 Element issuerSerial = doc.createElement("", "IssuerSerial");
			 issuerSerial.addChild(Node.ELEMENT, X509IssuerName);
			 issuerSerial.addChild(Node.ELEMENT, X509SerialNumber);
			 
			 //DigestMethod
			 Element digestMethod = doc.createElement("", "ds:DigestMethod");
			 digestMethod.setAttribute(null, "Algorithm", _digest_algorithm_URI);
			 digestMethod.addChild(Node.TEXT, "");
			 //DigestValue
			 Element digestValue = doc.createElement("", "ds:DigestValue");
			 MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
			 //TODO: Azt hiszem ez az amit hashelni kell

		     messageDigest.update(xcert.getEncoded());

		     byte[] bufout = messageDigest.digest();
		     byte[] data_shabinary_base64encoded = org.bouncycastle.util.encoders.Base64.encode(bufout);
		     digestValue.addChild(Node.TEXT,XadesUtil.toString(data_shabinary_base64encoded));
			 
		     //CertDigest
		     Element certDigest = doc.createElement("", "CertDigest");
		     certDigest.addChild(Node.ELEMENT, digestMethod);
		     certDigest.addChild(Node.ELEMENT, digestValue);
			 //Cert
			 Element cert = doc.createElement("","Cert");
			 cert.setAttribute(null, "URI", "#EnvelopingSignature-0-Signature-0-Object-0-QualifyingProperties-0-UnsignedProperties-0-UnsignedSignatureProperties-0-CertificateValues-0-EncapsulatedX509Certificate-"+String.valueOf(counter));
			 cert.addChild(Node.ELEMENT, certDigest);
			 cert.addChild(Node.ELEMENT, issuerSerial);
			 
			 certRefs.addChild(Node.ELEMENT, cert);
			 counter++;
		 }
		 
		 
		 //CompleteCertificateRefs
		 Element completeCertificateRefs = doc.createElement("", "CompleteCertificateRefs");
		 completeCertificateRefs.addChild(Node.ELEMENT,certRefs);
		 
		 return completeCertificateRefs;
		
	}
	
	///////////////////
	//CertificateValues
	///////////////////
	private Element getCertificateValues() throws KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException{
		 Certificate[] certchain = keystore.getCertificateChain(alias);
		 
		 //CompleteCertificateRefs
		 Element certificateValues = doc.createElement("", "CertificateValues");
		 
		 int counter = 0;
		 for(Certificate c:certchain){
			 X509Certificate xcert = (X509Certificate) c;

			 //EncapsulatedX509Certificate
			 Element cert = doc.createElement("","EncapsulatedX509Certificate");
			 cert.setAttribute(null, "Id", "EnvelopingSignature-0-Signature-0-Object-0-QualifyingProperties-0-UnsignedProperties-0-UnsignedSignatureProperties-0-CertificateValues-0-EncapsulatedX509Certificate-"+String.valueOf(counter));
			 cert.addChild(Node.TEXT, XadesUtil.toString(org.bouncycastle.util.encoders.Base64.encode(xcert.getEncoded())));
			 
			 certificateValues.addChild(Node.ELEMENT, cert);
			 counter++;
		 }
		 
		 return certificateValues;
		
	}
	
	
	
}
