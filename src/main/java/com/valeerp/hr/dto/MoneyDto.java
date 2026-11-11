package com.valeerp.hr.dto;

import com.valeerp.kernel.Money;
import jakarta.validation.constraints.NotNull;

import java.math.BigDecimal;

public class MoneyDto {

    @NotNull(message = "El monto es obligatorio")
    private BigDecimal amount;

    private String currency;

    public BigDecimal getAmount() {
        return amount;
    }

    public void setAmount(BigDecimal amount) {
        this.amount = amount;
    }

    public String getCurrency() {
        return currency;
    }

    public void setCurrency(String currency) {
        this.currency = currency;
    }

    public static MoneyDto from(Money money) {
        MoneyDto dto = new MoneyDto();
        dto.setAmount(money.amount());
        dto.setCurrency(money.currencyCode());
        return dto;
    }
}
