package com.edisa.galileo.digitalsign.signatures;

import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalSignature;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
public class DigestDocToSignExternalSignature implements ExternalSignature {

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
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        return messageDigest.digest(message);
    }

}
