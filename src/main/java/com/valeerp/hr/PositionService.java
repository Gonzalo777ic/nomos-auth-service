package com.valeerp.hr;

import com.valeerp.hr.dto.CreatePositionRequest;
import com.valeerp.hr.dto.PositionResponse;
import com.valeerp.hr.dto.UpdatePositionRequest;
import com.valeerp.kernel.Actors;
import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.company.CompanyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
public class PositionService {

    private final PositionRepository positionRepository;
    private final CompanyRepository companyRepository;

    public PositionService(PositionRepository positionRepository, CompanyRepository companyRepository) {
        this.positionRepository = positionRepository;
        this.companyRepository = companyRepository;
    }

    @Transactional(readOnly = true)
    public List<PositionResponse> listByCompany(Long companyId) {
        requireCompany(companyId);
        return positionRepository.findByCompanyId(companyId).stream().map(PositionResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public PositionResponse get(Long id) {
        return PositionResponse.from(requirePosition(id));
    }

    @Transactional
    public PositionResponse create(CreatePositionRequest request) {
        requireCompany(request.getCompanyId());
        String code = request.getCode().trim();
        if (positionRepository.existsByCompanyIdAndCodeIgnoreCase(request.getCompanyId(), code)) {
            throw new DomainException("Ya existe un puesto activo con ese código");
        }
        Position position = Position.open(request.getCompanyId(), code, request.getName());
        return PositionResponse.from(positionRepository.save(position));
    }

    @Transactional
    public PositionResponse update(Long id, UpdatePositionRequest request) {
        Position position = requirePosition(id);
        String code = request.getCode().trim();
        positionRepository.findByCompanyIdAndCodeIgnoreCase(position.getCompanyId(), code).ifPresent(other -> {
            if (!other.getId().equals(id)) {
                throw new DomainException("Ya existe un puesto activo con ese código");
            }
        });
        position.rename(code, request.getName());
        return PositionResponse.from(positionRepository.save(position));
    }

    @Transactional
    public void retire(Long id) {
        Position position = requirePosition(id);
        position.retire(Actors.current(), Instant.now());
        positionRepository.save(position);
    }

    private void requireCompany(Long companyId) {
        if (companyId == null) {
            throw new DomainException("La compañía es obligatoria");
        }
        if (!companyRepository.existsById(companyId)) {
            throw new DomainException("Compañía no encontrada");
        }
    }

    private Position requirePosition(Long id) {
        if (id == null) {
            throw new DomainException("El puesto es obligatorio");
        }
        return positionRepository.findById(id)
                .orElseThrow(() -> new DomainException("Puesto no encontrado"));
    }
}
