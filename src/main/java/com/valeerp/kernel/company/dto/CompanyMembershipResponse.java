package com.valeerp.kernel.company.dto;

import com.valeerp.kernel.company.CompanyMembership;

public class CompanyMembershipResponse {

    private final Long id;
    private final Long companyId;
    private final Long userId;
    private final String role;

    private CompanyMembershipResponse(Long id, Long companyId, Long userId, String role) {
        this.id = id;
        this.companyId = companyId;
        this.userId = userId;
        this.role = role;
    }

    public static CompanyMembershipResponse from(CompanyMembership membership) {
        return new CompanyMembershipResponse(
                membership.getId(),
                membership.getCompanyId(),
                membership.getUserId(),
                membership.getRole().name()
        );
    }

    public Long getId() {
        return id;
    }

    public Long getCompanyId() {
        return companyId;
    }

    public Long getUserId() {
        return userId;
    }

    public String getRole() {
        return role;
    }
}
