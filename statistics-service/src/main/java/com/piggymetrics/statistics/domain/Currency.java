package com.piggymetrics.statistics.domain;

public enum Currency {

    USD, HKD, CNY;

    public static Currency getBase() {
        return USD;
    }
}
