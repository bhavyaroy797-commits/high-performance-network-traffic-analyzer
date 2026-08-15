CREATE DATABASE network_analyzer;
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE network_analyzer;

DROP TABLE IF EXISTS network_anomalies;

CREATE TABLE network_anomalies (
    id              BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
    event_timestamp TIMESTAMP(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    source_ip       VARCHAR(45)      NOT NULL,
    source_port     SMALLINT UNSIGNED    NULL,
    dest_ip         VARCHAR(45)      NOT NULL,
    dest_port       SMALLINT UNSIGNED    NULL,
    protocol        VARCHAR(20)      NOT NULL,
    packet_length   INT UNSIGNED     NOT NULL,
    threat_type     VARCHAR(150)     NOT NULL DEFAULT 'Unclassified anomaly',
    severity        ENUM('low','medium','high','critical')
                                     NOT NULL DEFAULT 'high',
    PRIMARY KEY (id),
    INDEX idx_event_timestamp (event_timestamp),
    INDEX idx_severity (severity)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  ROW_FORMAT=DYNAMIC;

DROP TABLE IF EXISTS capture_stats;

CREATE TABLE capture_stats (
    id                      TINYINT UNSIGNED NOT NULL DEFAULT 1,
    packets_per_sec         INT UNSIGNED     NOT NULL DEFAULT 0,
    active_tcp_connections  INT UNSIGNED     NOT NULL DEFAULT 0,
    updated_at              TIMESTAMP(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
                                              ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    CONSTRAINT chk_capture_stats_single_row CHECK (id = 1)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

INSERT INTO capture_stats (id, packets_per_sec, active_tcp_connections)
VALUES (1, 0, 0);

DROP TABLE IF EXISTS capture_control;

CREATE TABLE capture_control (
    id          TINYINT UNSIGNED NOT NULL DEFAULT 1,
    is_active   TINYINT(1)       NOT NULL DEFAULT 1,
    updated_at  TIMESTAMP(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
                                  ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    CONSTRAINT chk_capture_control_single_row CHECK (id = 1)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

INSERT INTO capture_control (id, is_active)
VALUES (1, 1);