package com.valeerp.hr;

import com.valeerp.hr.dto.CancelBookRequest;
import com.valeerp.hr.dto.CompleteContractRequest;
import com.valeerp.hr.dto.ContractResponse;
import com.valeerp.hr.dto.CreateContractRequest;
import com.valeerp.hr.dto.MoneyDto;
import com.valeerp.kernel.Actors;
import com.valeerp.kernel.Currency;
import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.Money;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Libro de contratos. Sin delete físico: activar / completar / anular por estado.
 */
@Service
public class EmploymentContractService {

    private final EmploymentContractRepository contractRepository;
    private final EmployeeRepository employeeRepository;
    private final HrProperties properties;

    public EmploymentContractService(
            EmploymentContractRepository contractRepository,
            EmployeeRepository employeeRepository,
            HrProperties properties
    ) {
        this.contractRepository = contractRepository;
        this.employeeRepository = employeeRepository;
        this.properties = properties;
    }

    @Transactional(readOnly = true)
    public List<ContractResponse> listByEmployee(Long employeeId) {
        requireEmployee(employeeId);
        return contractRepository.findByEmployeeId(employeeId).stream().map(ContractResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public List<ContractResponse> listByCompany(Long companyId) {
        if (companyId == null) {
            throw new DomainException("La compañía es obligatoria");
        }
        return contractRepository.findByCompanyId(companyId).stream().map(ContractResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public ContractResponse get(Long id) {
        return ContractResponse.from(requireContract(id));
    }

    @Transactional
    public ContractResponse createDraft(CreateContractRequest request) {
        Employee employee = requireEmployee(request.getEmployeeId());
        ContractType type = resolveContractType(request.getContractType());
        Money wage = resolveWage(request.getWage());
        EmploymentContract contract = EmploymentContract.draft(
                employee.getId(),
                employee.getCompanyId(),
                type,
                request.getStartsOn(),
                request.getEndsOn(),
                wage,
                Instant.now()
        );
        return ContractResponse.from(contractRepository.save(contract));
    }

    @Transactional
    public ContractResponse activate(Long id) {
        EmploymentContract contract = requireContract(id);
        contract.activate(Instant.now());
        return ContractResponse.from(contractRepository.save(contract));
    }

    @Transactional
    public ContractResponse complete(Long id, CompleteContractRequest request) {
        EmploymentContract contract = requireContract(id);
        contract.complete(Instant.now(), request == null ? null : request.getEndsOn());
        return ContractResponse.from(contractRepository.save(contract));
    }

    @Transactional
    public ContractResponse cancel(Long id, CancelBookRequest request) {
        EmploymentContract contract = requireContract(id);
        String reason = request == null ? null : request.getReason();
        contract.cancel(Actors.current(), Instant.now(), reason);
        return ContractResponse.from(contractRepository.save(contract));
    }

    private ContractType resolveContractType(String raw) {
        if (raw == null || raw.isBlank()) {
            return properties.getDefaultContractType();
        }
        return ContractType.require(raw);
    }

    private Money resolveWage(MoneyDto dto) {
        if (dto == null || dto.getAmount() == null) {
            throw new DomainException("La remuneración es obligatoria");
        }
        Currency currency = (dto.getCurrency() == null || dto.getCurrency().isBlank())
                ? properties.getDefaultWageCurrency()
                : Currency.of(dto.getCurrency());
        return Money.of(dto.getAmount(), currency);
    }

    private Employee requireEmployee(Long employeeId) {
        if (employeeId == null) {
            throw new DomainException("El empleado es obligatorio");
        }
        return employeeRepository.findById(employeeId)
                .orElseThrow(() -> new DomainException("Empleado no encontrado"));
    }

    private EmploymentContract requireContract(Long id) {
        if (id == null) {
            throw new DomainException("El contrato es obligatorio");
        }
        return contractRepository.findById(id)
                .orElseThrow(() -> new DomainException("Contrato no encontrado"));
    }
}
