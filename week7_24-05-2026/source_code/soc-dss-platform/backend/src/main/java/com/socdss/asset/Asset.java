package com.socdss.asset;

import jakarta.persistence.*;

@Entity
@Table(name = "assets")
public class Asset {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    private String ipAddress;

    @Column(nullable = false)
    private String criticality;

    @Column(nullable = false)
    private String exposure;

    private String owner;
    private String environment;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    public String getCriticality() { return criticality; }
    public void setCriticality(String criticality) { this.criticality = criticality; }
    public String getExposure() { return exposure; }
    public void setExposure(String exposure) { this.exposure = exposure; }
    public String getOwner() { return owner; }
    public void setOwner(String owner) { this.owner = owner; }
    public String getEnvironment() { return environment; }
    public void setEnvironment(String environment) { this.environment = environment; }
}
