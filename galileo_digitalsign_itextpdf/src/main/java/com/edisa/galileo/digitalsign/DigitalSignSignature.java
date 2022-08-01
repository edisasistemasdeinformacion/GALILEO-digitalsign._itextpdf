package com.edisa.galileo.digitalsign;

import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalSignature;

import java.security.GeneralSecurityException;

public class DigitalSignSignature implements ExternalSignature {

    private byte[] signedHash;

    public DigitalSignSignature(byte[] signedHash) {
        this.signedHash = signedHash;
    }

    @Override
    public String getHashAlgorithm() {
        return DigestAlgorithms.SHA256;
    }

    @Override
    public String getEncryptionAlgorithm() {
        return "RSA";
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        return this.signedHash;
    }
}
