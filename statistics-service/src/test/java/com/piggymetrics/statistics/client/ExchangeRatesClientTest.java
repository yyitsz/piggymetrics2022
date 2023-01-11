package com.piggymetrics.statistics.client;

import com.piggymetrics.statistics.domain.Currency;
import com.piggymetrics.statistics.domain.ExchangeRatesContainer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
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
        assertNotNull(container.getRates().get(Currency.EUR.name()));
        assertNotNull(container.getRates().get(Currency.RUB.name()));
    }

    @Test
    public void shouldRetrieveExchangeRatesForSpecifiedCurrency() {

        Currency requestedCurrency = Currency.EUR;
        ExchangeRatesContainer container = client.getRates(Currency.getBase());

        assertEquals(container.getDate(), LocalDate.now());
        assertEquals(container.getBase(), Currency.getBase());

        assertNotNull(container.getRates());
        assertNotNull(container.getRates().get(requestedCurrency.name()));
    }
}