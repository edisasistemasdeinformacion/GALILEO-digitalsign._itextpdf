package com.edisa.galileo.digitalsign;

public class DocToSignResponse {

    private byte[] digestHash;
    private byte[] docToSignHash;

    public DocToSignResponse() {
    }

    public byte[] getDigestHash() {
        return digestHash;
    }

    public void setDigestHash(byte[] digestHash) {
        this.digestHash = digestHash;
    }

    public byte[] getDocToSignHash() {
        return docToSignHash;
    }

    public void setDocToSignHash(byte[] docToSignHash) {
        this.docToSignHash = docToSignHash;
    }
}
