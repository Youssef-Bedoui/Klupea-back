-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema mydb
-- -----------------------------------------------------
-- -----------------------------------------------------
-- Schema klupea
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema klupea
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `klupea` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci ;
USE `klupea` ;

-- -----------------------------------------------------
-- Table `klupea`.`products`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `klupea`.`products` (
  `ID` INT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(80) NOT NULL,
  `image` VARCHAR(255) NOT NULL,
  `price` VARCHAR(45) NOT NULL,
  `prevPrice` VARCHAR(45) NULL DEFAULT NULL,
  `gender` VARCHAR(45) NOT NULL,
  `category` VARCHAR(45) NOT NULL,
  `brand` VARCHAR(45) NULL DEFAULT NULL,
  `arrivalDate` VARCHAR(155) NULL DEFAULT NULL,
  PRIMARY KEY (`ID`))
ENGINE = InnoDB
AUTO_INCREMENT = 852
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `klupea`.`users`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `klupea`.`users` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `userName` VARCHAR(155) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `email` VARCHAR(100) NOT NULL,
  `address` VARCHAR(155) NOT NULL,
  `city` VARCHAR(100) NOT NULL,
  `phone` VARCHAR(55) NOT NULL,
  `activationCode` VARCHAR(155) NOT NULL,
  `isActive` VARCHAR(45) NOT NULL DEFAULT '"false"',
  PRIMARY KEY (`id`),
  UNIQUE INDEX `email_UNIQUE` (`email` ASC) VISIBLE)
ENGINE = InnoDB
AUTO_INCREMENT = 85
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `klupea`.`bag`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `klupea`.`bag` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `productID` INT NOT NULL,
  `orderSize` VARCHAR(45) NOT NULL,
  `orderQuantity` INT NOT NULL,
  `userID` INT NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `userID_idx` (`userID` ASC) VISIBLE,
  INDEX `productID_idx` (`productID` ASC) INVISIBLE,
  CONSTRAINT `product_id`
    FOREIGN KEY (`productID`)
    REFERENCES `klupea`.`products` (`ID`),
  CONSTRAINT `userID`
    FOREIGN KEY (`userID`)
    REFERENCES `klupea`.`users` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB
AUTO_INCREMENT = 614
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `klupea`.`news_subscriptions`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `klupea`.`news_subscriptions` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `user_email` VARCHAR(155) NOT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 7
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `klupea`.`orders`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `klupea`.`orders` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `userID` INT NOT NULL,
  `orderID` VARCHAR(100) NOT NULL,
  `productID` INT NOT NULL,
  `quantity` VARCHAR(50) NOT NULL,
  `orderStatus` VARCHAR(155) NOT NULL DEFAULT 'Preparing Order',
  PRIMARY KEY (`id`),
  INDEX `userID_idx` (`userID` ASC) VISIBLE,
  INDEX `orderID_index` (`orderID` ASC) VISIBLE,
  INDEX `product_id_idx` (`productID` ASC) VISIBLE,
  CONSTRAINT `id_product`
    FOREIGN KEY (`productID`)
    REFERENCES `klupea`.`products` (`ID`)
    ON DELETE CASCADE,
  CONSTRAINT `id_user`
    FOREIGN KEY (`userID`)
    REFERENCES `klupea`.`users` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB
AUTO_INCREMENT = 281
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `klupea`.`sizes`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `klupea`.`sizes` (
  `sizeID` INT NOT NULL AUTO_INCREMENT,
  `size` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`sizeID`))
ENGINE = InnoDB
AUTO_INCREMENT = 163
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `klupea`.`product_sizes`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `klupea`.`product_sizes` (
  `productID` INT NOT NULL,
  `sizeID` INT NOT NULL,
  PRIMARY KEY (`productID`, `sizeID`),
  INDEX `sizeID` (`sizeID` ASC) VISIBLE,
  CONSTRAINT `product_sizes_ibfk_1`
    FOREIGN KEY (`productID`)
    REFERENCES `klupea`.`products` (`ID`)
    ON DELETE CASCADE,
  CONSTRAINT `product_sizes_ibfk_2`
    FOREIGN KEY (`sizeID`)
    REFERENCES `klupea`.`sizes` (`sizeID`)
    ON DELETE CASCADE)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `klupea`.`user_has_orders`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `klupea`.`user_has_orders` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `userID` INT NOT NULL,
  `orderID` VARCHAR(150) NOT NULL,
  `paymentDate` VARCHAR(155) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `user_id_idx` (`userID` ASC) VISIBLE,
  INDEX `order_id_idx` (`orderID` ASC) VISIBLE,
  CONSTRAINT `order_id`
    FOREIGN KEY (`orderID`)
    REFERENCES `klupea`.`orders` (`orderID`)
    ON DELETE CASCADE,
  CONSTRAINT `user_id`
    FOREIGN KEY (`userID`)
    REFERENCES `klupea`.`users` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB
AUTO_INCREMENT = 169
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `klupea`.`wishlist`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `klupea`.`wishlist` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `userID` INT NOT NULL,
  `productID` INT NOT NULL,
  `product_image` VARCHAR(255) NOT NULL,
  `product_name` VARCHAR(155) NOT NULL,
  `unit_price` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `fk_wishlist_users1` (`userID` ASC) VISIBLE,
  INDEX `product_id_idx` (`productID` ASC) VISIBLE,
  CONSTRAINT `fk_wishlist_users1`
    FOREIGN KEY (`userID`)
    REFERENCES `klupea`.`users` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT `product_Id2`
    FOREIGN KEY (`productID`)
    REFERENCES `klupea`.`products` (`ID`))
ENGINE = InnoDB
AUTO_INCREMENT = 21
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
