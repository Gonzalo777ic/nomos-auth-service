package com.valeerp.hr;

import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.Money;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Transiciones de libros RRHH con fixtures literales. Sin Spring ni Auth0.
 */
class HrBookStateTest {

    @Test
    void contractActivatesCompletesAndRejectsDeletePath() {
        EmploymentContract contract = EmploymentContract.draft(
                10L,
                1L,
                ContractType.INDEFINITE,
                LocalDate.parse("2026-01-01"),
                null,
                Money.pen(new BigDecimal("2500.00")),
                Instant.parse("2026-01-01T10:00:00Z")
        );
        assertEquals(ContractStatus.DRAFT, contract.getStatus());

        contract.activate(Instant.parse("2026-01-02T10:00:00Z"));
        assertEquals(ContractStatus.ACTIVE, contract.getStatus());

        contract.complete(Instant.parse("2026-12-31T10:00:00Z"), LocalDate.parse("2026-12-31"));
        assertEquals(ContractStatus.COMPLETED, contract.getStatus());

        assertThrows(
                DomainException.class,
                () -> contract.cancel("admin", Instant.parse("2027-01-01T10:00:00Z"), "tarde")
        );
    }

    @Test
    void absenceApproveCompleteAndCancelDraft() {
        Absence absence = Absence.draft(
                10L,
                1L,
                AbsenceType.VACATION,
                LocalDate.parse("2026-07-01"),
                LocalDate.parse("2026-07-15"),
                "Vacaciones anuales",
                Instant.parse("2026-06-01T10:00:00Z")
        );
        absence.approve(Instant.parse("2026-06-02T10:00:00Z"));
        assertEquals(AbsenceStatus.APPROVED, absence.getStatus());
        absence.complete(Instant.parse("2026-07-16T10:00:00Z"));
        assertEquals(AbsenceStatus.COMPLETED, absence.getStatus());

        Absence draft = Absence.draft(
                11L,
                1L,
                AbsenceType.SICK,
                LocalDate.parse("2026-08-01"),
                LocalDate.parse("2026-08-03"),
                null,
                Instant.parse("2026-08-01T08:00:00Z")
        );
        draft.cancel("hr", Instant.parse("2026-08-01T09:00:00Z"), "Error de registro");
        assertEquals(AbsenceStatus.CANCELLED, draft.getStatus());
    }

    @Test
    void employeeIsDistinctFromIdentityUserLink() {
        Employee employee = Employee.hire(
                1L,
                "E-001",
                "Ana Pérez",
                2L,
                3L,
                LocalDate.parse("2025-03-01"),
                null,
                "ana@empresa.local"
        );
        assertEquals(null, employee.getUserId());
        employee.linkUser(99L);
        assertEquals(99L, employee.getUserId());
        employee.unlinkUser();
        assertEquals(null, employee.getUserId());
    }
}
