-- MySQL Script generated by MySQL Workbench
-- Вт 10 июл 2018 21:06:08
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

-- -----------------------------------------------------
-- Schema switch_snmp_lldp_t1
-- -----------------------------------------------------
DROP SCHEMA IF EXISTS `switch_snmp_lldp_t1` ;

-- -----------------------------------------------------
-- Schema switch_snmp_lldp_t1
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `switch_snmp_lldp_t1` DEFAULT CHARACTER SET utf8 ;
USE `switch_snmp_lldp_t1` ;

-- -----------------------------------------------------
-- Table `switch_snmp_lldp_t1`.`switches`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `switch_snmp_lldp_t1`.`switches` ;

CREATE TABLE IF NOT EXISTS `switch_snmp_lldp_t1`.`switches` (
  `id_switches` INT NOT NULL AUTO_INCREMENT,
  `ip` VARCHAR(15) NOT NULL,
  `FDQN` VARCHAR(100) NULL,
  PRIMARY KEY (`id_switches`),
  UNIQUE INDEX `ip_UNIQUE` (`ip` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `switch_snmp_lldp_t1`.`ports`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `switch_snmp_lldp_t1`.`ports` ;

CREATE TABLE IF NOT EXISTS `switch_snmp_lldp_t1`.`ports` (
  `id_ports` INT NOT NULL AUTO_INCREMENT,
  `port_number` INT NOT NULL,
  `id_switches` INT NOT NULL,
  PRIMARY KEY (`id_ports`),
  INDEX `fk_ports_switches_idx` (`id_switches` ASC),
  CONSTRAINT `fk_ports_switches`
    FOREIGN KEY (`id_switches`)
    REFERENCES `switch_snmp_lldp_t1`.`switches` (`id_switches`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `switch_snmp_lldp_t1`.`requests`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `switch_snmp_lldp_t1`.`requests` ;

CREATE TABLE IF NOT EXISTS `switch_snmp_lldp_t1`.`requests` (
  `id_requests` INT NOT NULL AUTO_INCREMENT,
  `DATE` DATETIME NOT NULL,
  PRIMARY KEY (`id_requests`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `switch_snmp_lldp_t1`.`statistics_ports`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `switch_snmp_lldp_t1`.`statistics_ports` ;

CREATE TABLE IF NOT EXISTS `switch_snmp_lldp_t1`.`statistics_ports` (
  `id_ports` INT NOT NULL,
  `port_description` VARCHAR(255) NULL,
  `port_speed` INT NULL,
  `port_mac` VARCHAR(17) NOT NULL,
  `port_status` INT NULL DEFAULT 0,
  `port_uptime` VARCHAR(50) NULL,
  `port_in_octets` BIGINT NULL,
  `port_out_octets` BIGINT NULL,
  `id_requests` INT NOT NULL,
  INDEX `fk_statistics_ports_ports1_idx` (`id_ports` ASC),
  INDEX `fk_statistics_ports_requests1_idx` (`id_requests` ASC),
  CONSTRAINT `fk_statistics_ports_ports1`
    FOREIGN KEY (`id_ports`)
    REFERENCES `switch_snmp_lldp_t1`.`ports` (`id_ports`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_statistics_ports_requests1`
    FOREIGN KEY (`id_requests`)
    REFERENCES `switch_snmp_lldp_t1`.`requests` (`id_requests`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `switch_snmp_lldp_t1`.`statistics_switch`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `switch_snmp_lldp_t1`.`statistics_switch` ;

CREATE TABLE IF NOT EXISTS `switch_snmp_lldp_t1`.`statistics_switch` (
  `id_switches` INT NOT NULL,
  `id_requests` INT NOT NULL,
  `switch_description` VARCHAR(255) NULL,
  `switch_uptime` VARCHAR(50) NULL,
  `cpu_utilization` INT NULL,
  `memory_utilization` INT NULL,
  INDEX `fk_statistics_switch_switches1_idx` (`id_switches` ASC),
  INDEX `fk_statistics_switch_requests1_idx` (`id_requests` ASC),
  CONSTRAINT `fk_statistics_switch_switches1`
    FOREIGN KEY (`id_switches`)
    REFERENCES `switch_snmp_lldp_t1`.`switches` (`id_switches`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_statistics_switch_requests1`
    FOREIGN KEY (`id_requests`)
    REFERENCES `switch_snmp_lldp_t1`.`requests` (`id_requests`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `switch_snmp_lldp_t1`.`FDB_tables`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `switch_snmp_lldp_t1`.`FDB_tables` ;

CREATE TABLE IF NOT EXISTS `switch_snmp_lldp_t1`.`FDB_tables` (
  `id_requests` INT NOT NULL,
  `id_ports` INT NOT NULL,
  `mac_address` VARCHAR(17) NULL DEFAULT 'UNKNOWN_MAC',
  `VID` INT NULL DEFAULT 1,
  `ip_address` VARCHAR(15) NULL DEFAULT 'NO_IP_ADDR',
  INDEX `fk_FDB_tables_requests1_idx` (`id_requests` ASC),
  INDEX `fk_FDB_tables_ports1_idx` (`id_ports` ASC),
  CONSTRAINT `fk_FDB_tables_requests1`
    FOREIGN KEY (`id_requests`)
    REFERENCES `switch_snmp_lldp_t1`.`requests` (`id_requests`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_FDB_tables_ports1`
    FOREIGN KEY (`id_ports`)
    REFERENCES `switch_snmp_lldp_t1`.`ports` (`id_ports`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `switch_snmp_lldp_t1`.`vlan_table`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `switch_snmp_lldp_t1`.`vlan_table` ;

CREATE TABLE IF NOT EXISTS `switch_snmp_lldp_t1`.`vlan_table` (
  `VID` INT NULL DEFAULT 1,
  `host_amount` INT NULL,
  `id_switches` INT NOT NULL,
  `id_requests` INT NOT NULL,
  INDEX `fk_vlan_table_switches1_idx` (`id_switches` ASC),
  INDEX `fk_vlan_table_requests1_idx` (`id_requests` ASC),
  CONSTRAINT `fk_vlan_table_switches1`
    FOREIGN KEY (`id_switches`)
    REFERENCES `switch_snmp_lldp_t1`.`switches` (`id_switches`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_vlan_table_requests1`
    FOREIGN KEY (`id_requests`)
    REFERENCES `switch_snmp_lldp_t1`.`requests` (`id_requests`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `switch_snmp_lldp_t1`.`LLDP_table`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `switch_snmp_lldp_t1`.`LLDP_table` ;

CREATE TABLE IF NOT EXISTS `switch_snmp_lldp_t1`.`LLDP_table` (
  `id_ports` INT NOT NULL,
  `neighbor_mac` VARCHAR(17) NOT NULL,
  `neighbor_port` VARCHAR(50) NULL DEFAULT 'Unnamed port',
  `id_requests` INT NOT NULL,
  INDEX `fk_LLDP_table_ports1_idx` (`id_ports` ASC),
  INDEX `fk_LLDP_table_requests1_idx` (`id_requests` ASC),
  CONSTRAINT `fk_LLDP_table_ports1`
    FOREIGN KEY (`id_ports`)
    REFERENCES `switch_snmp_lldp_t1`.`ports` (`id_ports`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_LLDP_table_requests1`
    FOREIGN KEY (`id_requests`)
    REFERENCES `switch_snmp_lldp_t1`.`requests` (`id_requests`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
