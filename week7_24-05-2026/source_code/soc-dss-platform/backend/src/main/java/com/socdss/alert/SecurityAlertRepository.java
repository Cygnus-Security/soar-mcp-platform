package com.socdss.alert;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, Long> {
    List<SecurityAlert> findByIncidentType(String incidentType);

    @Query("select distinct a.incidentType from SecurityAlert a where a.incidentType is not null")
    List<String> findDistinctIncidentTypes();
}
