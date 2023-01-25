package com.piggymetrics.statistics.client;

import com.piggymetrics.statistics.domain.Currency;
import com.piggymetrics.statistics.domain.ExchangeRatesContainer;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.HashMap;

@Component
public class ExchangeRatesClientFallback implements ExchangeRatesClient {

    @Override
    public ExchangeRatesContainer getRates(Currency base) {
        ExchangeRatesContainer container = new ExchangeRatesContainer();
        container.setBase(Currency.getBase());
        HashMap<String, BigDecimal> rates = new HashMap<>();
        rates.put(Currency.EUR.toString(), new BigDecimal("0.8"));
        rates.put(Currency.RUB.toString(), new BigDecimal("10.0"));
        rates.put(Currency.USD.toString(), new BigDecimal("1"));
        container.setRates(rates);
        return container;
    }
}
