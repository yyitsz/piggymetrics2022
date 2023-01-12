package com.piggymetrics.statistics.client;

import com.piggymetrics.statistics.domain.Currency;
import com.piggymetrics.statistics.domain.ExchangeRatesContainer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
@DirtiesContext
public class ExchangeRatesClientTest {

    @Autowired
    private ExchangeRatesClient client;

    @Test
    public void shouldRetrieveExchangeRates() {

        ExchangeRatesContainer container = client.getRates(Currency.getBase());

        assertEquals(container.getDate(), LocalDate.now());
        assertEquals(container.getBase(), Currency.getBase());

        assertNotNull(container.getRates());
        assertNotNull(container.getRates().get(Currency.USD.name()));
        assertNotNull(container.getRates().get(Currency.HKD.name()));
        assertNotNull(container.getRates().get(Currency.CNY.name()));
    }

    @Test
    public void shouldRetrieveExchangeRatesForSpecifiedCurrency() {

        Currency requestedCurrency = Currency.HKD;
        ExchangeRatesContainer container = client.getRates(Currency.getBase());

        assertEquals(container.getDate(), LocalDate.now());
        assertEquals(container.getBase(), Currency.getBase());

        assertNotNull(container.getRates());
        assertNotNull(container.getRates().get(requestedCurrency.name()));
    }
}