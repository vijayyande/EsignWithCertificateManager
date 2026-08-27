package in.gov.cca.esign.service;

import in.gov.cca.esign.domain.EsignTransaction;
import in.gov.cca.esign.model.xml.esign.EsignRequest;
import in.gov.cca.esign.model.xml.esign.EsignResponse;
import in.gov.cca.esign.model.xml.esign.EsignStatusRequest;

import java.util.Date;
import java.util.List;

public interface EsignService {

    EsignResponse processEsignRequest(EsignRequest request, String requestXml, String aspSignature);

    EsignResponse checkSigningStatus(EsignStatusRequest request, String requestXml, String aspSignature);

    EsignResponse getTransactionResponse(String transactionId);

    List<EsignTransaction> getTransactionsByAsp(String aspId);

    void callbackResponse(String responseUrl, EsignResponse response);

    EsignTransaction getTransaction(String transactionId);

    /**
     * After the user has been authenticated (eKYC callback or dev auth),
     * generates keypair, requests certificate from CM, signs all document
     * hashes, embeds timestamps, and sends the signed response to the ASP.
     */
    EsignResponse completeSigning(String transactionId, String signerId, Date signingTime);
}