package com.piggymetrics.statistics.client;

import com.piggymetrics.statistics.domain.Currency;
import com.piggymetrics.statistics.domain.ExchangeRatesContainer;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.HashMap;

@Component
public class ExchangeRatesClientFallback implements ExchangeRatesClient {

    @Override
    public ExchangeRatesContainer getRates(Currency base) {
        ExchangeRatesContainer container = new ExchangeRatesContainer();
        container.setBase(Currency.getBase());
        HashMap<String, BigDecimal> rates = new HashMap<>();
        rates.put(Currency.HKD.toString(), new BigDecimal("7.8"));
        rates.put(Currency.CNY.toString(), new BigDecimal("6.9"));
        rates.put(Currency.USD.toString(), new BigDecimal("1"));
        container.setRates(rates);
        return container;
    }
}
