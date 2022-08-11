package com.edisa.galileo.digitalsign.signatures;

import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalSignature;
import org.jboss.aerogear.security.otp.Totp;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONObject;

import static org.assertj.core.api.Assertions.assertThat;

public class DigitalSignExternalSignature implements ExternalSignature {

    private static final String HASH_256_ALG = "2.16.840.1.101.3.4.2.1";
    private static final String URL_BASE = "https://qscd-dev.digitalsign.pt/";
    private static final String TOKEN = "c4b0ae29-3107-40ce-bf67-a9a7c79372f6";
    private static final String SECRET_AUTHORIZER = "A7GZNWVTA2FG556Q";
    private static final String TOPTP_ID = "hea593gibsvldk2c3nvhba8tt7fkuomegv3t";
    private static final String CERT_ALIAS = "oyeyw6ulocautq4kl75mxd8u01h1rmqz";

    private HttpClient client;

    public DigitalSignExternalSignature() {
        client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(20))
                .build();
    }

    @Override
    public String getHashAlgorithm() {
        return DigestAlgorithms.SHA256;
    }

    @Override
    public String getEncryptionAlgorithm() {
        return "RSA";
    }

    private HttpRequest getRequest(String path, String json) {
      return HttpRequest.newBuilder()
                .uri(URI.create(URL_BASE+path))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer "+TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(json))
              .build();
    }



    /**
     * Obtener un TOPTP_VALUE válido
     * @return
     */
    private String getToptpValue() {
        String totpValue = null;
        boolean valid = false;
        int numIters = 1;
        while (!valid && numIters < 5) {
            String totpValueTest = null;
            try {
                Totp generator = new Totp(SECRET_AUTHORIZER);
                totpValueTest = generator.now();
                JSONObject jsonRequest = new JSONObject();
                jsonRequest.put("certAlias", CERT_ALIAS);
                jsonRequest.put("totpID", TOPTP_ID);
                jsonRequest.put("totpValue", totpValueTest);

                HttpRequest request = getRequest("totp/validateTOTP", jsonRequest.toString());
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                System.out.println("response status: "+response.statusCode()+", body: "+response.body());

                if (200 == response.statusCode()) {
                    totpValue = totpValueTest;
                    valid = true;
                }
            } catch(Exception ex) {
                ex.printStackTrace();
            }

            if (!valid) {
                System.out.println("El toptpValue: "+totpValueTest+" NO es válido, buscar otro");
                numIters = numIters + 1;
            }
        }
        return totpValue;
    }

    /**
     * Realizar solicitud a servicio "sigCompleteTOTPPolling" recuperando el "sigReqId" necesario para consultar en "sigComplete"
     * @param hashToSign64
     * @param toptpValue
     * @return
     */
    private String sigCompleteTOTPPolling(String hashToSign64, String toptpValue) {
        String sigReqId = null;
        try {
            String docAlias = "doc_sign_"+ UUID.randomUUID().toString()+".pdf";

            JSONObject jsonRequest = new JSONObject();
            jsonRequest.put("certAlias",CERT_ALIAS);
            jsonRequest.put("sigReqDescr", "Firmar Documento");
            jsonRequest.put("totpID",TOPTP_ID);
            jsonRequest.put("totpValue",toptpValue);
            JSONArray jsonArrayDocsToSign = new JSONArray();
            JSONObject jsonDocToSign = new JSONObject();
            jsonDocToSign.put("docAlias", docAlias);
            jsonDocToSign.put("hashAlg", HASH_256_ALG);
            jsonDocToSign.put("hashToSign_64", hashToSign64);
            jsonArrayDocsToSign.put(jsonDocToSign);
            jsonRequest.put("docsToSign",jsonArrayDocsToSign);

            HttpRequest request = getRequest("totp/sigCompleteTOTPPolling", jsonRequest.toString());
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("response status: "+response.statusCode()+", body: "+response.body());

            if (200 == response.statusCode()) {
                JSONObject jsonResponse = new JSONObject(response.body());
                sigReqId = jsonResponse.getString("sigReqID");
            }

        } catch(Exception ex) {
            ex.printStackTrace();
        }

        return sigReqId;
    }

    /**
     * Realizar comunicación con servicio "sigFinalize" con reintentos si la respuesta no es 200
     * @param sigReqId
     * @return
     */
    private String sigFinalize(String sigReqId) {
        String hashSig = null;

        boolean valid = false;
        int numIters = 1;
        while (!valid && numIters < 5) {

            Integer waitTimeSeconds = 1;

            try {
                JSONObject jsonRequest = new JSONObject();
                jsonRequest.put("sigReqID", sigReqId);

                HttpRequest request = getRequest("totp/sigFinalize", jsonRequest.toString());
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                System.out.println("response status: "+response.statusCode()+", body: "+response.body());

                JSONObject jsonResponse = new JSONObject(response.body());

                if (200 == response.statusCode()) {
                    hashSig = jsonResponse.getJSONArray("signedDocsInfo").getJSONObject(0).getString("hashSig");
                    valid = true;
                } else {
                    String errorCode = jsonResponse.getString("errorCode");
                    String errorDescription = jsonResponse.getString("error_description");
                    if ("028001".equalsIgnoreCase(errorCode)) {
                        Integer retryAfter = jsonResponse.getInt("retryAfter");
                        waitTimeSeconds = retryAfter;
                    }
                }
            } catch(Exception ex) {
                ex.printStackTrace();
            }

            if (!valid) {
                try {
                    System.out.println("No ha finalizado el proceso de firmado - Realizar una espera de " + waitTimeSeconds + "s");
                    Thread.sleep(waitTimeSeconds * 1000);
                    numIters = numIters + 1;
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }

        }
        return hashSig;
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        byte[] hashSigned = null;

        try {
            //Prepare the digest of the PDF
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest(message);
            System.out.println("Byte array length: " + hash.length);
            String digest = new String(Base64.getEncoder().encode(hash));
            System.out.println("Digest: " + digest);

            String toptpValue = getToptpValue();
            System.out.println("toptpValue: "+toptpValue);
            assertThat(toptpValue).overridingErrorMessage("No se ha obtenido un toptpValue válido").isNotEmpty();

            String sigReqId = sigCompleteTOTPPolling(digest, toptpValue);
            System.out.println("sigReqId: "+sigReqId);
            assertThat(sigReqId).overridingErrorMessage("No se ha obtenido el sigReqId en el proceso sigCompleteTOTPPolling").isNotEmpty();

            String hashSignedB64 = sigFinalize(sigReqId);
            System.out.println("hashSignedB64: "+hashSignedB64);
            assertThat(hashSignedB64).overridingErrorMessage("No se ha obtenido el hashSigned en el proceso sigFinalize").isNotEmpty();
            hashSigned = Base64.getDecoder().decode(hashSignedB64);

        } catch(Exception ex) {
            ex.printStackTrace();
        }

        return hashSigned;
    }
}
