package com.javabuilder.taskpilot.common;

public enum TokenType {
    BEARER;

    public String getValue() {
        return name().charAt(0) + name().substring(1).toLowerCase();
    }
}
