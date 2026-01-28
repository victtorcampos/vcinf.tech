package tech.vcinftech.ecosystem.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DashboardSummary implements Serializable {

    private static final long serialVersionUID = 1L; 
    
    private long totalUsers;
    private long activeSessions;
}
