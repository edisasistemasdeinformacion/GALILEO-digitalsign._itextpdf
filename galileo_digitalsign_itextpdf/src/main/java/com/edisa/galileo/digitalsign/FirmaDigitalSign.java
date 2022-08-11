package com.edisa.galileo.digitalsign;

import static org.assertj.core.api.Assertions.assertThat;

import com.edisa.galileo.digitalsign.signatures.DigestDocToSignExternalSignature;
import com.edisa.galileo.digitalsign.signatures.DigitalSignExternalSignature;
import com.edisa.galileo.digitalsign.signatures.PreCalculatedSignSignature;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;

import java.io.*;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FirmaDigitalSign {

    private static SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private static void log(String prefijo, Date date) {
        System.out.println(prefijo + " " + date_format.format(date));
    }
    private static void log(String prefijo, byte[] data) { System.out.println(prefijo + " " + new String(Base64.getEncoder().encode(data))); }
    private static void log(String prefijo, String data) { System.out.println(prefijo + " " + data); }
    private static void log(String prefijo, Integer data) { System.out.println(prefijo + " " + data); }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    static Logger LOG = LoggerFactory.getLogger(FirmaDigitalSign.class);

    private byte[] pdfContent;
    private byte[] certificateChain;
    private byte[] signedHash;
    private byte[] digestHash;
    private String reason;
    private String location;
    private Character pdfVersion;
    private Float posX;
    private Float posY;
    private Float width;
    private Float height;
    private byte[] image;

    private String tmpFile;

    protected FirmaDigitalSign() {
        //tmpFile = getTmpFile();
    }

    public byte[] getPdfContent() {
        return pdfContent;
    }

    public void setPdfContent(byte[] pdfContent) {
        this.pdfContent = pdfContent;
    }

    public byte[] getCertificateChain() {
        return certificateChain;
    }

    public void setCertificateChain(byte[] certificateChain) {
        this.certificateChain = certificateChain;
    }

    public byte[] getSignedHash() {
        return signedHash;
    }
    public void setSignedHash(byte[] signedHash) {
        this.signedHash = signedHash;
    }

    public byte[] getDigestHash() {
        return digestHash;
    }
    public void setDigestHash(byte[] digestHash) {
        this.digestHash = digestHash;
    }
    public String getReason() {
        return reason;
    }
    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getLocation() {
        return location;
    }
    public void setLocation(String location) {
        this.location = location;
    }

    public Character getPdfVersion() { return pdfVersion; }
    public void setPdfVersion(Character pdfVersion) { this.pdfVersion = pdfVersion; }

    public Float getPosX() { return posX; }
    public void setPosX(Float posX) { this.posX = posX; }

    public Float getPosY() { return posY; }
    public void setPosY(Float posY) { this.posY = posY; }

    public Float getWidth() { return width; }
    public void setWidth(Float width) { this.width = width; }

    public Float getHeight() { return height; }
    public void setHeight(Float height) { this.height = height; }

    public byte[] getImage() { return image; }
    public void setImage(byte[] image) { this.image = image; }

    private String getTmpFile() {
        return System.getProperty("java.io.tmpdir") + "tmp_" + UUID.randomUUID() + "-signed.pdf";
    }

    private void closeSilent(Closeable closeable) {
        if (closeable != null) try { closeable.close(); } catch(Exception ex) {}
    }
    private void deleteTmpFile() {
        new File(tmpFile).delete();
    }

//    public DocToSignResponse getDocHashToSign64() throws IOException {
//        DocToSignResponse response = new DocToSignResponse();
//
//
//        String hashToSign64 = null;
//
//        Collection collection = null;
//        ByteArrayOutputStream baos = null;
//        ByteArrayInputStream bais = null;
//        try {
//
//            assertThat(certificateChain).overridingErrorMessage("certificateChain obligatorio").isNotNull();
//            assertThat(pdfContent).overridingErrorMessage("pdfContent obligatorio").isNotNull();
//
//            collection = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(this.certificateChain));
//            Certificate[] certChain = new Certificate[collection.size()];
//            Iterator iterator = collection.iterator();
//            int i = 0;
//            while (iterator.hasNext()) {
//                certChain[i++] = (Certificate) iterator.next();
//            }
//
//            baos = new ByteArrayOutputStream();
//            bais = new ByteArrayInputStream(this.pdfContent);
//            PdfReader reader = new PdfReader(bais);
//
//            PdfStamper stamper = PdfStamper.createSignature(reader, baos, (this.pdfVersion != null ? this.pdfVersion : '\0'));
//            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
//
//            if (this.reason != null) {
//                LOG.info("Añadimos a la appearance la reason:" + this.reason);
//                appearance.setReason(this.reason);
//            } else {
//                LOG.info("No Añadimos a la appearance la reason");
//            }
//            if (this.location != null) {
//                LOG.info("Añadimos a la appearance la location:" + this.location);
//                appearance.setLocation(this.location);
//            } else {
//                LOG.info("No Añadimos a la appearance la location");
//            }
//
//            float llx = (this.posX != null) ? this.posX : 36;
//            float lly = (this.posY != null) ? this.posY : 748;
//            float urx = (this.width != null) ? (this.width + llx) : 144;
//            float ury = (this.height != null) ? (this.height + lly) : 780;
//
//            LOG.info("Seteado la visibilidad de la firma con los siguientes parámetros: llx:" + llx + ", lly:" + lly + ", urx:" + urx + ", ury:" + ury);
//
//            if (this.image != null) {
//                LOG.info("Agregar Firma sobre un LOGO");
//            } else {
//                LOG.info("Agregar Firma sobre un Rectangulo");
//                appearance.setVisibleSignature(new Rectangle(llx, lly, urx, ury), 1, "sig");
//            }
//
//            //Extraído de MakeSignature
//            ExternalSignature externalSignature = new DigestDocToSignExternalSignature();
//            ExternalDigest externalDigest = new BouncyCastleDigest();
//
//            Collection<CrlClient> crlList = null;
//            OcspClient ocspClient = null;
//            TSAClient tsaClient = null;
//            int estimatedSize = 0;
//            MakeSignature.CryptoStandard sigtype = MakeSignature.CryptoStandard.CMS;
//            SignaturePolicyIdentifier signaturePolicy = null;
//
//            Collection<byte[]> crlBytes = null;
//            i = 0;
//            while (crlBytes == null && i < certChain.length)
//                crlBytes = MakeSignature.processCrl(certChain[i++], crlList);
//            if (estimatedSize == 0) {
//                estimatedSize = 8192;
//                if (crlBytes != null) {
//                    for (byte[] element : crlBytes) {
//                        estimatedSize += element.length + 10;
//                    }
//                }
//                if (ocspClient != null)
//                    estimatedSize += 4192;
//                if (tsaClient != null)
//                    estimatedSize += 4192;
//            }
//            appearance.setCertificate(certChain[0]);
//            if (sigtype == MakeSignature.CryptoStandard.CADES) {
//                appearance.addDeveloperExtension(PdfDeveloperExtension.ESIC_1_7_EXTENSIONLEVEL2);
//            }
//            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, sigtype == MakeSignature.CryptoStandard.CADES ? PdfName.ETSI_CADES_DETACHED : PdfName.ADBE_PKCS7_DETACHED);
//            dic.setReason(appearance.getReason());
//            dic.setLocation(appearance.getLocation());
//            dic.setSignatureCreator(appearance.getSignatureCreator());
//            dic.setContact(appearance.getContact());
//            dic.setDate(new PdfDate(appearance.getSignDate())); // time-stamp will over-rule this
//            appearance.setCryptoDictionary(dic);
//
//            HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
//            exc.put(PdfName.CONTENTS, new Integer(estimatedSize * 2 + 2));
//            appearance.preClose(exc);
//
//            String hashAlgorithm = externalSignature.getHashAlgorithm();
//            PdfPKCS7 sgn = new PdfPKCS7(null, certChain, hashAlgorithm, null, externalDigest, false);
//            if (signaturePolicy != null) {
//                sgn.setSignaturePolicy(signaturePolicy);
//            }
//            InputStream data = appearance.getRangeStream();
//            byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest(hashAlgorithm));
//
//            byte[] ocsp = null;
//            if (certChain.length >= 2 && ocspClient != null) {
//                ocsp = ocspClient.getEncoded((X509Certificate) certChain[0], (X509Certificate) certChain[1], null);
//            }
//            byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, ocsp, crlBytes, sigtype);
//            byte[] extSignature = externalSignature.sign(sh);
//
//            response.setDigestHash(hash);
//            response.setDocToSignHash(extSignature);
//
//        } catch(Exception ex) {
//            LOG.error(ex.getMessage());
//            ex.printStackTrace();
//            throw new IOException(ex);
//        } finally {
//            closeSilent(bais);
//            closeSilent(baos);
//        }
//        return response;
//    }
//
//    public byte[] signPDF() throws IOException {
//        byte[] signedPDF = null;
//
//        Collection collection = null;
//        ByteArrayOutputStream baos = null;
//        ByteArrayInputStream bais = null;
//        try {
//
//            assertThat(certificateChain).overridingErrorMessage("certificateChain obligatorio").isNotNull();
//            assertThat(pdfContent).overridingErrorMessage("pdfContent obligatorio").isNotNull();
//            assertThat(signedHash).overridingErrorMessage("signedHash obligatorio").isNotNull();
//
//            collection = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(this.certificateChain));
//            Certificate[] certChain = new Certificate[collection.size()];
//            Iterator iterator = collection.iterator();
//            int i = 0;
//            while (iterator.hasNext()) {
//                certChain[i++] = (Certificate) iterator.next();
//            }
//
//            //baos = new ByteArrayOutputStream();
//            //bais = new ByteArrayInputStream(this.pdfContent);
//            //PdfReader reader = new PdfReader(bais);
//
//            FileOutputStream fOS = new FileOutputStream("C:\\Temp\\digitalsign\\PDFSignTest_signed.pdf");
//            PdfReader reader = new PdfReader("C:\\Temp\\digitalsign\\PDFSignTest.pdf");
//
//            PdfStamper stamper = PdfStamper.createSignature(reader, fOS, (this.pdfVersion != null ? this.pdfVersion : '\0'));
//            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
//            appearance.setSignDate(appearance.getSignDate());
//            if (this.reason != null) {
//                LOG.info("Añadimos a la appearance la reason:" + this.reason);
//                appearance.setReason(this.reason);
//            } else {
//                LOG.info("No Añadimos a la appearance la reason");
//            }
//            if (this.location != null) {
//                LOG.info("Añadimos a la appearance la location:" + this.location);
//                appearance.setLocation(this.location);
//            } else {
//                LOG.info("No Añadimos a la appearance la location");
//            }
//
//            float llx = (this.posX != null) ? this.posX : 36;
//            float lly = (this.posY != null) ? this.posY : 748;
//            float urx = (this.width != null) ? (this.width + llx) : 144;
//            float ury = (this.height != null) ? (this.height + lly) : 780;
//
//            LOG.info("Seteado la visibilidad de la firma con los siguientes parámetros: llx:" + llx + ", lly:" + lly + ", urx:" + urx + ", ury:" + ury);
//
//            if (this.image != null) {
//                LOG.info("Agregar Firma sobre un LOGO");
//            } else {
//                LOG.info("Agregar Firma sobre un Rectangulo");
//                appearance.setVisibleSignature(new Rectangle(llx, lly, urx, ury), 1, "sig");
//            }
//
//            //Extraído de MakeSignature
//            ExternalSignature externalSignature = new PreCalculatedSignSignature(this.signedHash);
//            ExternalDigest externalDigest = new BouncyCastleDigest();
//
//            Collection<CrlClient> crlList = null;
//            OcspClient ocspClient = null;
//            TSAClient tsaClient = null;
//            int estimatedSize = 0;
//            MakeSignature.CryptoStandard sigtype = MakeSignature.CryptoStandard.CMS;
//            SignaturePolicyIdentifier signaturePolicy = null;
//
//            Collection<byte[]> crlBytes = null;
//            i = 0;
//            while (crlBytes == null && i < certChain.length)
//                crlBytes = MakeSignature.processCrl(certChain[i++], crlList);
//            if (estimatedSize == 0) {
//                estimatedSize = 8192;
//                if (crlBytes != null) {
//                    for (byte[] element : crlBytes) {
//                        estimatedSize += element.length + 10;
//                    }
//                }
//                if (ocspClient != null)
//                    estimatedSize += 4192;
//                if (tsaClient != null)
//                    estimatedSize += 4192;
//            }
//            appearance.setCertificate(certChain[0]);
//            if (sigtype == MakeSignature.CryptoStandard.CADES) {
//                appearance.addDeveloperExtension(PdfDeveloperExtension.ESIC_1_7_EXTENSIONLEVEL2);
//            }
//            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, sigtype == MakeSignature.CryptoStandard.CADES ? PdfName.ETSI_CADES_DETACHED : PdfName.ADBE_PKCS7_DETACHED);
//            dic.setReason(appearance.getReason());
//            dic.setLocation(appearance.getLocation());
//            dic.setSignatureCreator(appearance.getSignatureCreator());
//            dic.setContact(appearance.getContact());
//            dic.setDate(new PdfDate(appearance.getSignDate())); // time-stamp will over-rule this
//            appearance.setCryptoDictionary(dic);
//
//            HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
//            exc.put(PdfName.CONTENTS, new Integer(estimatedSize * 2 + 2));
//            appearance.preClose(exc);
//
//            String hashAlgorithm = externalSignature.getHashAlgorithm();
//            PdfPKCS7 sgn = new PdfPKCS7(null, certChain, hashAlgorithm, null, externalDigest, false);
//            if (signaturePolicy != null) {
//                sgn.setSignaturePolicy(signaturePolicy);
//            }
//            //No usar el HASH calculado -> Enviar el anterior
//            //InputStream data = appearance.getRangeStream();
//            //byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest(hashAlgorithm));
//            byte hash[] = getDigestHash();
//
//            byte[] ocsp = null;
//            if (certChain.length >= 2 && ocspClient != null) {
//                ocsp = ocspClient.getEncoded((X509Certificate) certChain[0], (X509Certificate) certChain[1], null);
//            }
//            byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, ocsp, crlBytes, sigtype);
//            byte[] extSignature = externalSignature.sign(sh);
//            sgn.setExternalDigest(extSignature, null, externalSignature.getEncryptionAlgorithm());
//
//            byte[] encodedSig = sgn.getEncodedPKCS7(hash, tsaClient, ocsp, crlBytes, sigtype);
//
//            if (estimatedSize < encodedSig.length)
//                throw new IOException("Not enough space");
//
//            byte[] paddedSig = new byte[estimatedSize];
//            System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
//
//            PdfDictionary dic2 = new PdfDictionary();
//            dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
//            appearance.close(dic2);
//            //-------------------------------------------------------------------------------
//
//            //signedPDF = baos.toByteArray();
//        } catch(Exception ex) {
//            LOG.error(ex.getMessage());
//            ex.printStackTrace();
//            throw new IOException(ex);
//        } finally {
//            closeSilent(bais);
//            closeSilent(baos);
//        }
//        return signedPDF;
//    }

    public byte[] signPDF() throws IOException {
        byte[] signedPDF = null;

        Collection collection = null;
        ByteArrayOutputStream baos = null;
        ByteArrayInputStream bais = null;
        try {

            assertThat(certificateChain).overridingErrorMessage("certificateChain obligatorio").isNotNull();
            assertThat(pdfContent).overridingErrorMessage("pdfContent obligatorio").isNotNull();

            collection = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(this.certificateChain));
            Certificate[] certChain = new Certificate[collection.size()];
            Iterator iterator = collection.iterator();
            int i = 0;
            while (iterator.hasNext()) {
                certChain[i++] = (Certificate) iterator.next();
            }

            baos = new ByteArrayOutputStream();
            bais = new ByteArrayInputStream(this.pdfContent);
            PdfReader reader = new PdfReader(bais);

            PdfStamper stamper = PdfStamper.createSignature(reader, baos, (this.pdfVersion != null ? this.pdfVersion : '\0'));
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setSignDate(appearance.getSignDate());
            if (this.reason != null) {
                LOG.info("Añadimos a la appearance la reason:" + this.reason);
                appearance.setReason(this.reason);
            } else {
                LOG.info("No Añadimos a la appearance la reason");
            }
            if (this.location != null) {
                LOG.info("Añadimos a la appearance la location:" + this.location);
                appearance.setLocation(this.location);
            } else {
                LOG.info("No Añadimos a la appearance la location");
            }

            float llx = (this.posX != null) ? this.posX : 36;
            float lly = (this.posY != null) ? this.posY : 748;
            float urx = (this.width != null) ? (this.width + llx) : 144;
            float ury = (this.height != null) ? (this.height + lly) : 780;

            LOG.info("Seteado la visibilidad de la firma con los siguientes parámetros: llx:" + llx + ", lly:" + lly + ", urx:" + urx + ", ury:" + ury);

            if (this.image != null) {
                LOG.info("Agregar Firma sobre un LOGO");
            } else {
                LOG.info("Agregar Firma sobre un Rectangulo");
                appearance.setVisibleSignature(new Rectangle(llx, lly, urx, ury), 1, "sig");
            }

            ExternalSignature externalSignature = new DigitalSignExternalSignature();
            ExternalDigest externalDigest = new BouncyCastleDigest();
            MakeSignature.signDetached(appearance, externalDigest, externalSignature, certChain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);
            //-------------------------------------------------------------------------------

            signedPDF = baos.toByteArray();
        } catch(Exception ex) {
            LOG.error(ex.getMessage());
            ex.printStackTrace();
            throw new IOException(ex);
        } finally {
            closeSilent(bais);
            closeSilent(baos);
        }
        return signedPDF;
    }
}
