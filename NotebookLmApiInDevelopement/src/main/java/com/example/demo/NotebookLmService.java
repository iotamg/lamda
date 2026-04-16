package com.example.demo;

import com.google.auth.oauth2.GoogleCredentials;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.http.MediaType;
import java.io.IOException;
import java.util.Map;

@Service
public class NotebookLmService {

    private final RestClient restClient;
    private static final String PROJECT_NUMBER = "652182910829";

    public NotebookLmService() throws IOException {
        GoogleCredentials credentials = GoogleCredentials.getApplicationDefault()
                .createScoped("https://www.googleapis.com/auth/cloud-platform");
        credentials.refreshIfExpired();

        this.restClient = RestClient.builder()
                .baseUrl("https://discoveryengine.googleapis.com/v1alpha/projects/" + PROJECT_NUMBER + "/locations/global")
                .defaultHeader("Authorization", "Bearer " + credentials.getAccessToken().getTokenValue())
                .build();
    }

    public String generateAudio(String userPreferences) {
        try {
            Map notebookResponse = restClient.post()
                    .uri("/notebooks")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("displayName", "User Learning Notebook"))
                    .retrieve()
                    .body(Map.class);

            String notebookId = notebookResponse.get("name").toString();

            restClient.post()
                    .uri(notebookId + "/sources")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("inlineSource", Map.of("content", userPreferences)))
                    .retrieve()
                    .toBodilessEntity();

            Map audioResponse = restClient.post()
                    .uri(notebookId + "/audioOverviews")
                    .retrieve()
                    .body(Map.class);

            return "Success! AI Generation started: " + audioResponse.get("name");
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}