/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.auth.oauth2.it;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.auth.oauth2.TokenVerifier;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.*;

public class ITIAPTest {
  private final String SERVICE_ACCOUNT_FILE = "/home/chingor/Downloads/chingor-test-52d3f384cea6.json";

  private final String IAP_PROTECTED_RESOURCE = "https://print-iap-jwt-assertion-dot-cloud-iap-for-testing.uc.r.appspot.com/";
  private final String IAP_ISSUER = "https://cloud.google.com/iap";
  private final String IAP_CLIENT_ID = "1031437410300-ki5srmdg37qc6cl521dlqcmt4gbjufn5.apps.googleusercontent.com";
  private final String AUDIENCE_TO_VERIFY = "/projects/1031437410300/apps/cloud-iap-for-testing";

  private final String CLOUD_RUN_RESOURCE = "https://protected-resource-gmdw7sut5q-de.a.run.app/";

  @Test
  public void testCloudRun() throws IOException {
    InputStream inputStream = new FileInputStream(SERVICE_ACCOUNT_FILE);
    ServiceAccountCredentials serviceAccountCredentials = ServiceAccountCredentials.fromStream(inputStream);
    IdTokenCredentials credentials = IdTokenCredentials.newBuilder()
        .setIdTokenProvider(serviceAccountCredentials)
        .setTargetAudience(CLOUD_RUN_RESOURCE)
        .build();

    // Make a request to an IAP protected resource
    HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(credentials);
    HttpRequestFactory httpRequestFactory = new NetHttpTransport()
        .createRequestFactory(requestInitializer);
    HttpRequest httpRequest = httpRequestFactory.buildGetRequest(new GenericUrl(CLOUD_RUN_RESOURCE));
    HttpResponse httpResponse = httpRequest.execute();

    // Sample application returns the hello world for Cloud Run
    String pageContents =  httpResponse.parseAsString();
    System.out.println(pageContents);
    assertTrue(pageContents.contains("Congratulations"));
  }

  @Test
  public void testIapRequest() throws IOException {
    InputStream inputStream = new FileInputStream(SERVICE_ACCOUNT_FILE);
    ServiceAccountCredentials serviceAccountCredentials = ServiceAccountCredentials.fromStream(inputStream);
    IdTokenCredentials credentials = IdTokenCredentials.newBuilder()
        .setIdTokenProvider(serviceAccountCredentials)
        .setTargetAudience(IAP_CLIENT_ID)
        .build();

    // Make a request to an IAP protected resource
    HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(credentials);
    HttpRequestFactory httpRequestFactory = new NetHttpTransport()
        .createRequestFactory(requestInitializer);
    HttpRequest httpRequest = httpRequestFactory.buildGetRequest(new GenericUrl(IAP_PROTECTED_RESOURCE));
    HttpResponse httpResponse = httpRequest.execute();

    // Sample application return the
    String iapToken =  httpResponse.parseAsString();

    // Verify the token
    TokenVerifier tokenVerifier = TokenVerifier.newBuilder()
        .setIssuer(IAP_ISSUER)
        .setAudience(AUDIENCE_TO_VERIFY)
        .build();

    try {
      // verify signature, issuer, audience
      JsonWebSignature jsonWebSignature = tokenVerifier.verify(iapToken);

      // verify additional info/claims
      assertEquals(serviceAccountCredentials.getClientEmail(), jsonWebSignature.getPayload().get("email"));

      // debug
      System.out.println(jsonWebSignature);
    } catch (TokenVerifier.VerificationException e) {
      fail(e.getMessage());
    }
  }
}
