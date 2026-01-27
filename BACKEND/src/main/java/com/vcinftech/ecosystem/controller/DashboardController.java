package com.vcinftech.ecosystem.controller;

import com.vcinftech.ecosystem.dto.DashboardSummary;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    @GetMapping("/summary")
    @Cacheable("dashboard")
    public DashboardSummary getSummary() {
        // In a real app, this would fetch data from a service that queries the database.
        // Here, we simulate a delay and return mock data.
        try {
            Thread.sleep(1000); // Simulate latency
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return new DashboardSummary(150, 42);
    }
}
