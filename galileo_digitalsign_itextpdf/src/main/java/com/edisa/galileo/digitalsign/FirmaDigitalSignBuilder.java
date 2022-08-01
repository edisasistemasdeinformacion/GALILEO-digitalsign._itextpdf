package com.edisa.galileo.digitalsign;

public class FirmaDigitalSignBuilder {

    private byte[] pdfContent;
    private byte[] certificateChain;
    private byte[] signedHash;
    private String reason;
    private String location;
    private byte[] image;
    private Float posX;
    private Float posY;
    private Float width;
    private Float height;

    private FirmaDigitalSignBuilder() {
    }

    public static FirmaDigitalSignBuilder newInstance() {
        return new FirmaDigitalSignBuilder();
    }

    public FirmaDigitalSignBuilder setPdfContent(byte[] pdfContent) {
        this.pdfContent = pdfContent;
        return this;
    }

    public FirmaDigitalSignBuilder setCertificateChain(byte[] certificateChain) {
        this.certificateChain = certificateChain;
        return this;
    }

    public FirmaDigitalSignBuilder setSignedHash(byte[] signedHash) {
        this.signedHash = signedHash;
        return this;
    }

    public FirmaDigitalSignBuilder setReason(String reason) {
        this.reason = reason;
        return this;
    }

    public FirmaDigitalSignBuilder setLocation(String location) {
        this.location = location;
        return this;
    }

    public FirmaDigitalSignBuilder setPosX(Float posX) {
        this.posX = posX;
        return this;
    }

    public FirmaDigitalSignBuilder setPosY(Float posY) {
        this.posY = posY;
        return this;
    }

    public FirmaDigitalSignBuilder setWidth(Float width) {
        this.width = width;
        return this;
    }

    public FirmaDigitalSignBuilder setHeight(Float height) {
        this.height = height;
        return this;
    }

    public FirmaDigitalSignBuilder setImage(byte[] image) {
        this.image = image;
        return this;
    }

    public FirmaDigitalSign build() {
        FirmaDigitalSign build = new FirmaDigitalSign();

        build.setPdfContent(this.pdfContent);
        build.setCertificateChain(this.certificateChain);
        build.setSignedHash(this.signedHash);
        build.setReason(this.reason);
        build.setLocation(this.location);
        build.setPosX(this.posX);
        build.setPosY(this.posY);
        build.setWidth(this.width);
        build.setHeight(this.height);
        build.setImage(this.image);

        return build;
    }
}
