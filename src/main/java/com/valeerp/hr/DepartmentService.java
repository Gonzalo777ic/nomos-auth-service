package com.valeerp.hr;

import com.valeerp.hr.dto.CreateDepartmentRequest;
import com.valeerp.hr.dto.DepartmentResponse;
import com.valeerp.hr.dto.UpdateDepartmentRequest;
import com.valeerp.kernel.Actors;
import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.company.CompanyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
public class DepartmentService {

    private final DepartmentRepository departmentRepository;
    private final CompanyRepository companyRepository;

    public DepartmentService(DepartmentRepository departmentRepository, CompanyRepository companyRepository) {
        this.departmentRepository = departmentRepository;
        this.companyRepository = companyRepository;
    }

    @Transactional(readOnly = true)
    public List<DepartmentResponse> listByCompany(Long companyId) {
        requireCompany(companyId);
        return departmentRepository.findByCompanyId(companyId).stream().map(DepartmentResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public DepartmentResponse get(Long id) {
        return DepartmentResponse.from(requireDepartment(id));
    }

    @Transactional
    public DepartmentResponse create(CreateDepartmentRequest request) {
        requireCompany(request.getCompanyId());
        String code = request.getCode().trim();
        if (departmentRepository.existsByCompanyIdAndCodeIgnoreCase(request.getCompanyId(), code)) {
            throw new DomainException("Ya existe un departamento activo con ese código");
        }
        Department department = Department.open(request.getCompanyId(), code, request.getName());
        return DepartmentResponse.from(departmentRepository.save(department));
    }

    @Transactional
    public DepartmentResponse update(Long id, UpdateDepartmentRequest request) {
        Department department = requireDepartment(id);
        String code = request.getCode().trim();
        departmentRepository.findByCompanyIdAndCodeIgnoreCase(department.getCompanyId(), code).ifPresent(other -> {
            if (!other.getId().equals(id)) {
                throw new DomainException("Ya existe un departamento activo con ese código");
            }
        });
        department.rename(code, request.getName());
        return DepartmentResponse.from(departmentRepository.save(department));
    }

    @Transactional
    public void retire(Long id) {
        Department department = requireDepartment(id);
        department.retire(Actors.current(), Instant.now());
        departmentRepository.save(department);
    }

    private void requireCompany(Long companyId) {
        if (companyId == null) {
            throw new DomainException("La compañía es obligatoria");
        }
        if (!companyRepository.existsById(companyId)) {
            throw new DomainException("Compañía no encontrada");
        }
    }

    private Department requireDepartment(Long id) {
        if (id == null) {
            throw new DomainException("El departamento es obligatorio");
        }
        return departmentRepository.findById(id)
                .orElseThrow(() -> new DomainException("Departamento no encontrado"));
    }
}
