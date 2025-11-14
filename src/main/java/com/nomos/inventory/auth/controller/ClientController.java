package com.nomos.inventory.auth.controller;

import com.nomos.inventory.auth.model.Client;
import com.nomos.inventory.auth.model.DocumentType; // 💡 Importar el Enum
import com.nomos.inventory.auth.service.ClientService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth/clients")
public class ClientController {

    private final ClientService clientService;

    public ClientController(ClientService clientService) {
        this.clientService = clientService;
    }

    /**
     * 🌐 GET /api/auth/clients
     * Obtiene una lista de todos los clientes registrados.
     */
    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<Client>> getAllClients() {
        List<Client> clients = clientService.getAllClients();
        return ResponseEntity.ok(clients);
    }

    /**
     * 🌐 GET /api/auth/clients/document-types
     * Expone los valores del Enum DocumentType para ser usados en el frontend.
     * Se usa un DTO para enviar el nombre del enum (KEY) y su descripción.
     *
     * @return ResponseEntity con la lista de DocumentTypeDTO.
     */
    @GetMapping("/document-types") // <-- Nuevo Endpoint
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_SELLER')") // Permitir a vendedores verlo también
    public ResponseEntity<List<DocumentTypeDTO>> getDocumentTypes() {
        // Mapear los valores del enum a una lista de DTOs
        List<DocumentTypeDTO> dtos = Arrays.stream(DocumentType.values())
                .map(dt -> new DocumentTypeDTO(dt.name(), dt.getDescription()))
                .collect(Collectors.toList());

        return ResponseEntity.ok(dtos);
    }
}