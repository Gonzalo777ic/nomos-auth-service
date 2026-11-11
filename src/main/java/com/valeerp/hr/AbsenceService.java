package com.valeerp.hr;

import com.valeerp.hr.dto.AbsenceResponse;
import com.valeerp.hr.dto.CancelBookRequest;
import com.valeerp.hr.dto.CreateAbsenceRequest;
import com.valeerp.kernel.Actors;
import com.valeerp.kernel.DomainException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Libro de ausencias. Sin delete físico: aprobar / completar / anular por estado.
 */
@Service
public class AbsenceService {

    private final AbsenceRepository absenceRepository;
    private final EmployeeRepository employeeRepository;
    private final HrProperties properties;

    public AbsenceService(
            AbsenceRepository absenceRepository,
            EmployeeRepository employeeRepository,
            HrProperties properties
    ) {
        this.absenceRepository = absenceRepository;
        this.employeeRepository = employeeRepository;
        this.properties = properties;
    }

    @Transactional(readOnly = true)
    public List<AbsenceResponse> listByEmployee(Long employeeId) {
        requireEmployee(employeeId);
        return absenceRepository.findByEmployeeId(employeeId).stream().map(AbsenceResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public List<AbsenceResponse> listByCompany(Long companyId) {
        if (companyId == null) {
            throw new DomainException("La compañía es obligatoria");
        }
        return absenceRepository.findByCompanyId(companyId).stream().map(AbsenceResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public AbsenceResponse get(Long id) {
        return AbsenceResponse.from(requireAbsence(id));
    }

    @Transactional
    public AbsenceResponse createDraft(CreateAbsenceRequest request) {
        Employee employee = requireEmployee(request.getEmployeeId());
        AbsenceType type = resolveAbsenceType(request.getAbsenceType());
        Absence absence = Absence.draft(
                employee.getId(),
                employee.getCompanyId(),
                type,
                request.getStartsOn(),
                request.getEndsOn(),
                request.getReason(),
                Instant.now()
        );
        return AbsenceResponse.from(absenceRepository.save(absence));
    }

    @Transactional
    public AbsenceResponse approve(Long id) {
        Absence absence = requireAbsence(id);
        absence.approve(Instant.now());
        return AbsenceResponse.from(absenceRepository.save(absence));
    }

    @Transactional
    public AbsenceResponse complete(Long id) {
        Absence absence = requireAbsence(id);
        absence.complete(Instant.now());
        return AbsenceResponse.from(absenceRepository.save(absence));
    }

    @Transactional
    public AbsenceResponse cancel(Long id, CancelBookRequest request) {
        Absence absence = requireAbsence(id);
        String reason = request == null ? null : request.getReason();
        absence.cancel(Actors.current(), Instant.now(), reason);
        return AbsenceResponse.from(absenceRepository.save(absence));
    }

    private AbsenceType resolveAbsenceType(String raw) {
        if (raw == null || raw.isBlank()) {
            return properties.getDefaultAbsenceType();
        }
        return AbsenceType.require(raw);
    }

    private Employee requireEmployee(Long employeeId) {
        if (employeeId == null) {
            throw new DomainException("El empleado es obligatorio");
        }
        return employeeRepository.findById(employeeId)
                .orElseThrow(() -> new DomainException("Empleado no encontrado"));
    }

    private Absence requireAbsence(Long id) {
        if (id == null) {
            throw new DomainException("La ausencia es obligatoria");
        }
        return absenceRepository.findById(id)
                .orElseThrow(() -> new DomainException("Ausencia no encontrada"));
    }
}
