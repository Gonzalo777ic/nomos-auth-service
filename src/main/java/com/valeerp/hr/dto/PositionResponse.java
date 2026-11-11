package com.valeerp.hr.dto;

import com.valeerp.hr.Position;

public class PositionResponse {

    private final Long id;
    private final Long companyId;
    private final String code;
    private final String name;

    private PositionResponse(Long id, Long companyId, String code, String name) {
        this.id = id;
        this.companyId = companyId;
        this.code = code;
        this.name = name;
    }

    public static PositionResponse from(Position position) {
        return new PositionResponse(
                position.getId(),
                position.getCompanyId(),
                position.getCode(),
                position.getName()
        );
    }

    public Long getId() {
        return id;
    }

    public Long getCompanyId() {
        return companyId;
    }

    public String getCode() {
        return code;
    }

    public String getName() {
        return name;
    }
}
