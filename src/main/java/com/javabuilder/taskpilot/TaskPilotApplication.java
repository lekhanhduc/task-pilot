package com.javabuilder.taskpilot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class TaskPilotApplication {

    public static void main(String[] args) {
        SpringApplication.run(TaskPilotApplication.class, args);
    }

}
