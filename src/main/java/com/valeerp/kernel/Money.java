package com.valeerp.kernel;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Objects;

/**
 * Monto monetario inmutable. Escala fija 2; la moneda viaja con el valor.
 * Persistible como {@code @Embedded} con {@code @AttributeOverride} por campo.
 */
@Embeddable
public final class Money {

    public static final int SCALE = 2;
    public static final RoundingMode ROUNDING = RoundingMode.HALF_UP;

    @Column(precision = 19, scale = SCALE, nullable = false)
    private BigDecimal amount;

    @Column(name = "currency_code", length = 3, nullable = false)
    private String currencyCode;

    protected Money() {
    }

    private Money(BigDecimal amount, Currency currency) {
        this.amount = amount.setScale(SCALE, ROUNDING);
        this.currencyCode = currency.code();
    }

    @JsonCreator
    public static Money fromJson(
            @JsonProperty("amount") BigDecimal amount,
            @JsonProperty("currency") String currency
    ) {
        Currency resolved = (currency == null || currency.isBlank()) ? Currency.PEN : Currency.of(currency);
        return of(amount, resolved);
    }

    public static Money of(BigDecimal amount, Currency currency) {
        if (amount == null) {
            throw new DomainException("El monto es obligatorio");
        }
        if (currency == null) {
            throw new DomainException("La moneda es obligatoria");
        }
        if (amount.signum() < 0) {
            throw new DomainException("El monto no puede ser negativo");
        }
        return new Money(amount, currency);
    }

    public static Money of(BigDecimal amount, String currencyCode) {
        return of(amount, Currency.of(currencyCode));
    }

    public static Money pen(BigDecimal amount) {
        return of(amount, Currency.PEN);
    }

    public static Money zero(Currency currency) {
        return of(BigDecimal.ZERO, currency);
    }

    @JsonProperty("amount")
    public BigDecimal amount() {
        return amount;
    }

    public Currency currency() {
        return Currency.of(currencyCode);
    }

    @JsonProperty("currency")
    public String currencyCode() {
        return currencyCode;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Money money)) {
            return false;
        }
        return amount.compareTo(money.amount) == 0 && currencyCode.equals(money.currencyCode);
    }

    @Override
    public int hashCode() {
        return Objects.hash(amount.stripTrailingZeros(), currencyCode);
    }

    @Override
    public String toString() {
        return amount.toPlainString() + " " + currencyCode;
    }
}
