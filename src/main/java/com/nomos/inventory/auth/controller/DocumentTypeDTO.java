package com.nomos.inventory.auth.controller;

public class DocumentTypeDTO {
    private final String key;
    private final String description;

    public DocumentTypeDTO(String key, String description) {
        this.key = key;
        this.description = description;
    }

    // Getters (necesarios para que Jackson los serialice a JSON)
    public String getKey() {
        return key;
    }

    public String getDescription() {
        return description;
    }
}