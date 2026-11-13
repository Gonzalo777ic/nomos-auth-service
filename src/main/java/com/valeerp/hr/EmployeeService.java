package com.valeerp.hr;

import com.valeerp.inventory.auth.repository.UserRepository;
import com.valeerp.hr.dto.CreateEmployeeRequest;
import com.valeerp.hr.dto.EmployeeResponse;
import com.valeerp.hr.dto.LinkEmployeeUserRequest;
import com.valeerp.hr.dto.UpdateEmployeeRequest;
import com.valeerp.kernel.Actors;
import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.company.CompanyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Caso de uso de ficha RRHH. No posee ficha comercial; User solo por id opcional.
 */
@Service
public class EmployeeService {

    private final EmployeeRepository employeeRepository;
    private final DepartmentRepository departmentRepository;
    private final PositionRepository positionRepository;
    private final CompanyRepository companyRepository;
    private final UserRepository userRepository;

    public EmployeeService(
            EmployeeRepository employeeRepository,
            DepartmentRepository departmentRepository,
            PositionRepository positionRepository,
            CompanyRepository companyRepository,
            UserRepository userRepository
    ) {
        this.employeeRepository = employeeRepository;
        this.departmentRepository = departmentRepository;
        this.positionRepository = positionRepository;
        this.companyRepository = companyRepository;
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public List<EmployeeResponse> listByCompany(Long companyId) {
        requireCompany(companyId);
        return employeeRepository.findByCompanyId(companyId).stream().map(EmployeeResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public EmployeeResponse get(Long id) {
        return EmployeeResponse.from(requireEmployee(id));
    }

    @Transactional
    public EmployeeResponse create(CreateEmployeeRequest request) {
        requireCompany(request.getCompanyId());
        Department department = requireDepartmentInCompany(request.getDepartmentId(), request.getCompanyId());
        Position position = requirePositionInCompany(request.getPositionId(), request.getCompanyId());
        String code = request.getCode().trim();
        if (employeeRepository.existsByCompanyIdAndCodeIgnoreCase(request.getCompanyId(), code)) {
            throw new DomainException("Ya existe un empleado activo con ese código");
        }
        Long userId = request.getUserId();
        if (userId != null) {
            requireIdentityUser(userId);
            if (employeeRepository.existsByUserId(userId)) {
                throw new DomainException("El usuario de identidad ya está vinculado a un empleado");
            }
        }
        Employee employee = Employee.hire(
                request.getCompanyId(),
                code,
                request.getFullName(),
                department.getId(),
                position.getId(),
                request.getHireDate(),
                userId,
                request.getWorkEmail()
        );
        return EmployeeResponse.from(employeeRepository.save(employee));
    }

    @Transactional
    public EmployeeResponse update(Long id, UpdateEmployeeRequest request) {
        Employee employee = requireEmployee(id);
        requireDepartmentInCompany(request.getDepartmentId(), employee.getCompanyId());
        requirePositionInCompany(request.getPositionId(), employee.getCompanyId());
        String code = request.getCode().trim();
        employeeRepository.findByCompanyIdAndCodeIgnoreCase(employee.getCompanyId(), code).ifPresent(other -> {
            if (!other.getId().equals(id)) {
                throw new DomainException("Ya existe un empleado activo con ese código");
            }
        });
        employee.rename(code, request.getFullName());
        employee.reassignOrg(request.getDepartmentId(), request.getPositionId());
        employee.changeHireDate(request.getHireDate());
        employee.changeWorkEmail(request.getWorkEmail());
        return EmployeeResponse.from(employeeRepository.save(employee));
    }

    @Transactional
    public EmployeeResponse linkUser(Long id, LinkEmployeeUserRequest request) {
        Employee employee = requireEmployee(id);
        requireIdentityUser(request.getUserId());
        if (employeeRepository.existsByUserId(request.getUserId())
                && (employee.getUserId() == null || !employee.getUserId().equals(request.getUserId()))) {
            throw new DomainException("El usuario de identidad ya está vinculado a un empleado");
        }
        employee.linkUser(request.getUserId());
        return EmployeeResponse.from(employeeRepository.save(employee));
    }

    @Transactional
    public EmployeeResponse unlinkUser(Long id) {
        Employee employee = requireEmployee(id);
        employee.unlinkUser();
        return EmployeeResponse.from(employeeRepository.save(employee));
    }

    @Transactional
    public void retire(Long id) {
        Employee employee = requireEmployee(id);
        employee.retire(Actors.current(), Instant.now());
        employeeRepository.save(employee);
    }

    private void requireCompany(Long companyId) {
        if (companyId == null) {
            throw new DomainException("La compañía es obligatoria");
        }
        if (!companyRepository.existsById(companyId)) {
            throw new DomainException("Compañía no encontrada");
        }
    }

    private void requireIdentityUser(Long userId) {
        if (userId == null) {
            throw new DomainException("El userId es obligatorio");
        }
        if (!userRepository.existsById(userId)) {
            throw new DomainException("Usuario de identidad no encontrado");
        }
    }

    private Department requireDepartmentInCompany(Long departmentId, Long companyId) {
        Department department = departmentRepository.findById(departmentId)
                .orElseThrow(() -> new DomainException("Departamento no encontrado"));
        if (!department.getCompanyId().equals(companyId)) {
            throw new DomainException("El departamento no pertenece a la compañía");
        }
        return department;
    }

    private Position requirePositionInCompany(Long positionId, Long companyId) {
        Position position = positionRepository.findById(positionId)
                .orElseThrow(() -> new DomainException("Puesto no encontrado"));
        if (!position.getCompanyId().equals(companyId)) {
            throw new DomainException("El puesto no pertenece a la compañía");
        }
        return position;
    }

    private Employee requireEmployee(Long id) {
        if (id == null) {
            throw new DomainException("El empleado es obligatorio");
        }
        return employeeRepository.findById(id)
                .orElseThrow(() -> new DomainException("Empleado no encontrado"));
    }
}
