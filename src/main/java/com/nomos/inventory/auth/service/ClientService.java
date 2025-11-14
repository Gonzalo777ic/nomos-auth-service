package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.model.Client;
import com.nomos.inventory.auth.repository.ClientRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ClientService {

    private final ClientRepository clientRepository;

    public ClientService(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    /**
     * Obtiene la lista completa de todos los clientes.
     */
    public List<Client> getAllClients() {
        return clientRepository.findAll();
    }

    // Aquí iría la lógica para el Just-In-Time Provisioning de clientes si fuera necesario.
}