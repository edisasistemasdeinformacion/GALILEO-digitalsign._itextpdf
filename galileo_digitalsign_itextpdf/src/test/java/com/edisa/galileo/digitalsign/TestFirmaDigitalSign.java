package com.edisa.galileo.digitalsign;

import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestFirmaDigitalSign {


    @Test
    void signPDF() {
        //CertificateChain
        String b64CertificateChain = "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";
        byte[] certificateChain = Base64.getDecoder().decode(b64CertificateChain);

        String pdfFile = "C:\\Temp\\digitalsign\\PDFSignTest.pdf";
        String signedPdfFile = "C:\\Temp\\digitalsign\\PDFSignTest_signed.pdf";
        try {
            FileInputStream fl = new FileInputStream(pdfFile);
            FirmaDigitalSign firmaDigitalSign =
                    FirmaDigitalSignBuilder.newInstance()
                            .setCertificateChain(certificateChain)
                            .setPdfContent(fl.readAllBytes())
                            .setSignedHash("123456".getBytes(StandardCharsets.UTF_8))
                            .setReason("Reason: Teste")
                            .setLocation("Location: Teste")
                            .build();
            byte[] signedPDF = firmaDigitalSign.signPDF();

            try (FileOutputStream stream = new FileOutputStream(signedPdfFile)) {
                stream.write(signedPDF);
            }

            fl.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
