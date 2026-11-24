package com.zerotrust.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryPoolMXBean;

@SpringBootTest
@ActiveProfiles("test")
class MemoryFootprintMeasurementTest {

    @Test
    @DisplayName("Measure actual JVM memory footprint upon full Spring Boot startup")
    void measureMemoryFootprint() {
        System.gc();
        MemoryMXBean memoryMXBean = ManagementFactory.getMemoryMXBean();
        long heapUsed = memoryMXBean.getHeapMemoryUsage().getUsed() / (1024 * 1024);
        long heapCommitted = memoryMXBean.getHeapMemoryUsage().getCommitted() / (1024 * 1024);
        long nonHeapUsed = memoryMXBean.getNonHeapMemoryUsage().getUsed() / (1024 * 1024);
        long nonHeapCommitted = memoryMXBean.getNonHeapMemoryUsage().getCommitted() / (1024 * 1024);

        long metaspaceUsed = 0;
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            if (pool.getName().toLowerCase().contains("metaspace")) {
                metaspaceUsed = pool.getUsage().getUsed() / (1024 * 1024);
            }
        }

        long totalEstimatedRss = heapCommitted + nonHeapCommitted;
        System.out.println("==================================================");
        System.out.println("ACTUAL SPRING BOOT STARTUP MEMORY MEASUREMENTS:");
        System.out.println("Used Heap:          " + heapUsed + " MB");
        System.out.println("Committed Heap:     " + heapCommitted + " MB");
        System.out.println("Metaspace Used:     " + metaspaceUsed + " MB");
        System.out.println("Non-Heap Used:      " + nonHeapUsed + " MB");
        System.out.println("Non-Heap Committed: " + nonHeapCommitted + " MB");
        System.out.println("Total JVM Committed:" + totalEstimatedRss + " MB");
        System.out.println("Render Free Limit:  512 MB");
        System.out.println("==================================================");
    }
}
