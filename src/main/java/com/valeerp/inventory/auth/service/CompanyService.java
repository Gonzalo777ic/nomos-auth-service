package com.valeerp.inventory.auth.service;

import com.valeerp.inventory.auth.repository.UserRepository;
import com.valeerp.kernel.Actors;
import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.company.Company;
import com.valeerp.kernel.company.CompanyCurrency;
import com.valeerp.kernel.company.CompanyMembership;
import com.valeerp.kernel.company.CompanyMembershipRepository;
import com.valeerp.kernel.company.CompanyMembershipRole;
import com.valeerp.kernel.company.CompanyProperties;
import com.valeerp.kernel.company.CompanyRepository;
import com.valeerp.kernel.company.CompanyTimeZone;
import com.valeerp.kernel.company.dto.AssignMembershipRequest;
import com.valeerp.kernel.company.dto.CompanyMembershipResponse;
import com.valeerp.kernel.company.dto.CompanyResponse;
import com.valeerp.kernel.company.dto.CreateCompanyRequest;
import com.valeerp.kernel.company.dto.UpdateCompanyRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Caso de uso local de multi-compañía. No llama a otros servicios.
 */
@Service
public class CompanyService {

    private final CompanyRepository companyRepository;
    private final CompanyMembershipRepository membershipRepository;
    private final UserRepository userRepository;
    private final CompanyProperties properties;

    public CompanyService(
            CompanyRepository companyRepository,
            CompanyMembershipRepository membershipRepository,
            UserRepository userRepository,
            CompanyProperties properties
    ) {
        this.companyRepository = companyRepository;
        this.membershipRepository = membershipRepository;
        this.userRepository = userRepository;
        this.properties = properties;
    }

    @Transactional(readOnly = true)
    public List<CompanyResponse> listCompanies() {
        return companyRepository.findAll().stream().map(CompanyResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public CompanyResponse getCompany(Long id) {
        return CompanyResponse.from(requireCompany(id));
    }

    @Transactional
    public CompanyResponse createCompany(CreateCompanyRequest request) {
        String legalName = request.getLegalName() == null ? null : request.getLegalName().trim();
        if (legalName == null || legalName.isBlank()) {
            throw new DomainException("La razón social es obligatoria");
        }
        if (companyRepository.existsByLegalNameIgnoreCase(legalName)) {
            throw new DomainException("Ya existe una compañía con esa razón social");
        }

        CompanyCurrency currency = resolveCurrency(request.getCurrency());
        CompanyTimeZone timeZone = resolveTimeZone(request.getTimeZone());
        Company company = companyRepository.save(Company.register(legalName, currency, timeZone));

        if (request.getOwnerUserId() != null) {
            assignOwner(company.getId(), request.getOwnerUserId());
        }
        return CompanyResponse.from(company);
    }

    @Transactional
    public CompanyResponse updateCompany(Long id, UpdateCompanyRequest request) {
        Company company = requireCompany(id);
        String legalName = request.getLegalName().trim();
        companyRepository.findByLegalNameIgnoreCase(legalName).ifPresent(other -> {
            if (!other.getId().equals(id)) {
                throw new DomainException("Ya existe una compañía con esa razón social");
            }
        });
        company.rename(legalName);
        company.changeCurrency(CompanyCurrency.require(request.getCurrency()));
        company.changeTimeZone(CompanyTimeZone.require(request.getTimeZone()));
        return CompanyResponse.from(companyRepository.save(company));
    }

    @Transactional
    public void retireCompany(Long id) {
        Company company = requireCompany(id);
        company.retire(Actors.current(), Instant.now());
        companyRepository.save(company);
    }

    @Transactional(readOnly = true)
    public List<CompanyMembershipResponse> listMemberships(Long companyId) {
        requireCompany(companyId);
        return membershipRepository.findByCompanyId(companyId).stream()
                .map(CompanyMembershipResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<CompanyMembershipResponse> listMembershipsByUser(Long userId) {
        if (userId == null) {
            throw new DomainException("El usuario es obligatorio");
        }
        return membershipRepository.findByUserId(userId).stream()
                .map(CompanyMembershipResponse::from)
                .toList();
    }

    @Transactional
    public CompanyMembershipResponse assignMembership(Long companyId, AssignMembershipRequest request) {
        requireCompany(companyId);
        requireLocalUser(request.getUserId());
        if (membershipRepository.existsByCompanyIdAndUserId(companyId, request.getUserId())) {
            throw new DomainException("El usuario ya pertenece a esta compañía");
        }
        CompanyMembershipRole role = resolveMembershipRole(request.getRole());
        CompanyMembership membership = CompanyMembership.assign(companyId, request.getUserId(), role);
        return CompanyMembershipResponse.from(membershipRepository.save(membership));
    }

    @Transactional
    public CompanyMembershipResponse changeMembershipRole(Long companyId, Long membershipId, String role) {
        requireCompany(companyId);
        CompanyMembership membership = requireMembership(membershipId);
        if (!membership.getCompanyId().equals(companyId)) {
            throw new DomainException("La pertenencia no corresponde a la compañía");
        }
        membership.changeRole(CompanyMembershipRole.require(role));
        return CompanyMembershipResponse.from(membershipRepository.save(membership));
    }

    @Transactional
    public void retireMembership(Long companyId, Long membershipId) {
        requireCompany(companyId);
        CompanyMembership membership = requireMembership(membershipId);
        if (!membership.getCompanyId().equals(companyId)) {
            throw new DomainException("La pertenencia no corresponde a la compañía");
        }
        membership.retire(Actors.current(), Instant.now());
        membershipRepository.save(membership);
    }

    private void assignOwner(Long companyId, Long ownerUserId) {
        requireLocalUser(ownerUserId);
        CompanyMembership membership = CompanyMembership.assign(
                companyId,
                ownerUserId,
                CompanyMembershipRole.OWNER
        );
        membershipRepository.save(membership);
    }

    private void requireLocalUser(Long userId) {
        if (userId == null) {
            throw new DomainException("El usuario de la pertenencia es obligatorio");
        }
        if (!userRepository.existsById(userId)) {
            throw new DomainException("Usuario de identidad no encontrado");
        }
    }

    private CompanyCurrency resolveCurrency(String raw) {
        if (raw == null || raw.isBlank()) {
            return properties.getDefaultCurrency();
        }
        return CompanyCurrency.require(raw);
    }

    private CompanyTimeZone resolveTimeZone(String raw) {
        if (raw == null || raw.isBlank()) {
            return properties.getDefaultTimeZone();
        }
        return CompanyTimeZone.require(raw);
    }

    private CompanyMembershipRole resolveMembershipRole(String raw) {
        if (raw == null || raw.isBlank()) {
            return properties.getDefaultMembershipRole();
        }
        return CompanyMembershipRole.require(raw);
    }

    private Company requireCompany(Long id) {
        if (id == null) {
            throw new DomainException("La compañía es obligatoria");
        }
        return companyRepository.findById(id)
                .orElseThrow(() -> new DomainException("Compañía no encontrada"));
    }

    private CompanyMembership requireMembership(Long id) {
        if (id == null) {
            throw new DomainException("La pertenencia es obligatoria");
        }
        return membershipRepository.findById(id)
                .orElseThrow(() -> new DomainException("Pertenencia no encontrada"));
    }
}
