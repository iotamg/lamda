package com.example.demo;

import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api")
public class NotebookLmController {

    private final NotebookLmService notebookLmService;

    public NotebookLmController(NotebookLmService notebookLmService) {
        this.notebookLmService = notebookLmService;
    }

    @PostMapping("/generate-audio")
    public String handleRequest(@RequestBody String userPreferences) {
        return notebookLmService.generateAudio(userPreferences);
    }
}