package com.valeerp.kernel.company;

import com.valeerp.kernel.DomainException;

import java.time.ZoneId;
import java.util.Arrays;

/**
 * Zonas horarias admitidas para multi-compañía. El id IANA vive en el enum, no en controladores.
 */
public enum CompanyTimeZone {
    AMERICA_LIMA("America/Lima"),
    AMERICA_BOGOTA("America/Bogota"),
    AMERICA_MEXICO_CITY("America/Mexico_City"),
    UTC("UTC");

    private final String zoneId;

    CompanyTimeZone(String zoneId) {
        this.zoneId = zoneId;
    }

    public String zoneId() {
        return zoneId;
    }

    public ZoneId toZoneId() {
        return ZoneId.of(zoneId);
    }

    public static CompanyTimeZone require(String zoneIdOrName) {
        if (zoneIdOrName == null || zoneIdOrName.isBlank()) {
            throw new DomainException("La zona horaria es obligatoria");
        }
        String normalized = zoneIdOrName.trim();
        return Arrays.stream(values())
                .filter(tz -> tz.name().equalsIgnoreCase(normalized) || tz.zoneId.equalsIgnoreCase(normalized))
                .findFirst()
                .orElseThrow(() -> new DomainException("Zona horaria no soportada: " + zoneIdOrName));
    }
}
