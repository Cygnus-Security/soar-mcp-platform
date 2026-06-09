package com.socdss.asset;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AssetRepository extends JpaRepository<Asset, Long> {
    Optional<Asset> findByName(String name);
    Optional<Asset> findByIpAddress(String ipAddress);
}
