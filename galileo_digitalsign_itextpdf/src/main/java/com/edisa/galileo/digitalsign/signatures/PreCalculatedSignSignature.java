package com.edisa.galileo.digitalsign.signatures;

import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalSignature;

import java.security.GeneralSecurityException;

public class PreCalculatedSignSignature implements ExternalSignature {

    private byte[] signedHash;

    public PreCalculatedSignSignature(byte[] signedHash) {
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
