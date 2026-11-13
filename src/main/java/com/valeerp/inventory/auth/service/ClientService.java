package com.valeerp.inventory.auth.service;

import com.valeerp.inventory.auth.model.Client;
import com.valeerp.inventory.auth.repository.ClientRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ClientService {

    private final ClientRepository clientRepository;

    public ClientService(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }


    public List<Client> getAllClients() {
        return clientRepository.findAll();
    }

}