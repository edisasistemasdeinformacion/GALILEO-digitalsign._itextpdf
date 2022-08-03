package com.edisa.galileo.digitalsign;

import static org.assertj.core.api.Assertions.assertThat;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FirmaDigitalSign {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    static Logger LOG = LoggerFactory.getLogger(FirmaDigitalSign.class);

    private byte[] pdfContent;
    private byte[] certificateChain;
    private byte[] signedHash;
    private String reason;
    private String location;
    private Character pdfVersion;
    private Float posX;
    private Float posY;
    private Float width;
    private Float height;
    private byte[] image;
    protected FirmaDigitalSign() {
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

    public byte[] signPDF() throws IOException {
        byte[] signedPDF = null;

        Collection collection = null;
        ByteArrayOutputStream baos = null;
        ByteArrayInputStream bais = null;
        try {

            assertThat(signedHash).overridingErrorMessage("certificateChain obligatorio").isNotNull();
            assertThat(signedHash).overridingErrorMessage("pdfContent obligatorio").isNotNull();
            assertThat(signedHash).overridingErrorMessage("signedHash obligatorio").isNotNull();

            ExternalSignature externalSignature = new DigitalSignSignature(this.signedHash);

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

            PdfStamper stamper = PdfStamper.createSignature(reader, baos, (this.pdfVersion != null ? this.pdfVersion : '\0')); //null, false
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
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

            LOG.info("Seteado la visibilidad de la firma con los siguientes parámetros:\n" +
                    " - llx:" + llx + "\n" +
                    " - lly:" + lly + "\n" +
                    " - urx:" + urx + "\n" +
                    " - ury:" + ury);

            if (this.image != null) {
                LOG.info("Agregar Firma sobre un LOGO");
            } else {
                LOG.info("Agregar Firma sobre un Rectangulo");
                appearance.setVisibleSignature(new Rectangle(llx, lly, urx, ury), 1, "sig");
            }

            ExternalDigest digest = new BouncyCastleDigest();
            MakeSignature.signDetached(appearance, digest, externalSignature, certChain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);

            signedPDF = baos.toByteArray();

        } catch(Exception ex) {
            LOG.error(ex.getMessage());
            ex.printStackTrace();
            throw new IOException(ex);
        } finally {
            if (bais != null) try { bais.close(); } catch(Exception ex) {}
            if (baos != null) try { baos.close(); } catch(Exception ex) {}
        }
        return signedPDF;
    }
}
