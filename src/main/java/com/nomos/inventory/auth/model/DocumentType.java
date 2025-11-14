package com.nomos.inventory.auth.model;

public enum DocumentType {
    DNI("Documento Nacional de Identidad"),
    RUC("Registro Único de Contribuyentes"),
    PASSPORT("Pasaporte"),
    CE("Carné de Extranjería");

    private final String description;

    DocumentType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}